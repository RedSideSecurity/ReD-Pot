"""A small stateful model of iptables / ip6tables for unit tests (RC-22, VM defect B2).

It keeps chains and rules per tool and table, and enforces the kernel's per-hook restrictions the way the kernel
does: a match or target is checked against every built-in hook from which its chain can be REACHED (through
jumps), whenever a rule is added or a jump is inserted. A failure leaves the ruleset unchanged and returns rc 4 with
iptables-nft's message, which is what Ubuntu 26.04 (iptables 1.8.11, nf_tables) printed on the VM:
    iptables -A QA-PRE -m owner --uid-owner 10001 -j RETURN; iptables -I FORWARD 1 -j QA-PRE
    -> "RULE_INSERT failed (Invalid argument): rule in chain FORWARD", rc 4

Modelled restrictions (net/netfilter/xt_owner.c, ipt_REJECT.c, xt_TTL / ipt_TTL, xt_addrtype.c, iptables(8)):
  -m owner                 only OUTPUT / POSTROUTING
  -j REJECT                filter table only, hooks INPUT / FORWARD / OUTPUT
  -j TTL / HL              mangle table only
  addrtype --limit-iface-in   only PREROUTING / INPUT / FORWARD
  addrtype --limit-iface-out  only OUTPUT / POSTROUTING / FORWARD
  -i in a rule of built-in OUTPUT / POSTROUTING, -o in INPUT / PREROUTING (userspace check, rc 2)
Anything unknown to the model is accepted; this is not a packet evaluator (see _verdict in test_installer_wizard).
"""
import subprocess

BUILTIN = {
    "filter": ("INPUT", "FORWARD", "OUTPUT"),
    "mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
    "nat": ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"),
    "raw": ("PREROUTING", "OUTPUT"),
}
TARGETS = {"ACCEPT", "DROP", "RETURN", "REJECT", "LOG", "TTL", "HL", "MARK", "DNAT", "SNAT", "MASQUERADE"}
OWNER_HOOKS = {"OUTPUT", "POSTROUTING"}
REJECT_HOOKS = {"INPUT", "FORWARD", "OUTPUT"}
EINVAL = "RULE_INSERT failed (Invalid argument): rule in chain {}"


class IptModel:
    """run()-compatible stub. `docker`: None (no Docker), "iptables" (Docker's iptables backend: DOCKER-USER
    exists and FORWARD jumps to it) or "nftables" (Docker's nftables backend: no DOCKER-USER, nothing hooked).
    Commands that are not iptables/ip6tables are recorded and succeed. `fail(text)` forces a failure (rc 1)."""

    def __init__(self, docker=None, fail=lambda t: False, tools=("iptables", "ip6tables")):
        self.calls, self.errors, self.fail = [], [], fail
        self.tools = tools
        self.state = {}
        for tool in tools:
            self.state[tool] = {t: {c: [] for c in cs} for t, cs in BUILTIN.items()}
            if docker == "iptables":
                f = self.state[tool]["filter"]
                f["DOCKER-USER"] = [["-j", "RETURN"]]
                f["FORWARD"].append(["-j", "DOCKER-USER"])

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _tool(argv0):
        name = argv0.rsplit("/", 1)[-1]
        return name if name in ("iptables", "ip6tables") else None

    @staticmethod
    def _jump(rule):
        for k, o in enumerate(rule[:-1]):
            if o in ("-j", "-g"):
                return rule[k + 1]
        return None

    def _hooks(self, table, chains, chain):
        """Built-in hooks of `table` from which `chain` is reachable."""
        return {b for b in BUILTIN[table] if self._reach(chains, b, chain, set())}

    def _reach(self, chains, src, dst, seen):
        if src == dst:
            return True
        if src in seen:
            return False
        seen.add(src)
        return any(self._reach(chains, j, dst, seen) for r in chains.get(src, [])
                   for j in [self._jump(r)] if j in chains)

    def _valid(self, table, chains):
        """None if every rule is valid for every hook that reaches it, else the offending built-in chain."""
        for c, rules in chains.items():
            hooks = self._hooks(table, chains, c)
            for r in rules:
                tgt = self._jump(r)
                if "owner" in self._matches(r) and hooks - OWNER_HOOKS:
                    return sorted(hooks - OWNER_HOOKS)[0]
                if tgt == "REJECT" and (table != "filter" or hooks - REJECT_HOOKS):
                    return sorted(hooks - REJECT_HOOKS)[0] if hooks - REJECT_HOOKS else c
                if tgt in ("TTL", "HL") and table != "mangle":
                    return c
                if "--limit-iface-in" in r and hooks - {"PREROUTING", "INPUT", "FORWARD"}:
                    return sorted(hooks - {"PREROUTING", "INPUT", "FORWARD"})[0]
                if "--limit-iface-out" in r and hooks - {"OUTPUT", "POSTROUTING", "FORWARD"}:
                    return sorted(hooks - {"OUTPUT", "POSTROUTING", "FORWARD"})[0]
        return None

    @staticmethod
    def _matches(rule):
        return {rule[k + 1] for k, o in enumerate(rule[:-1]) if o == "-m"}

    # ---------------------------------------------------------------- run() stub
    def __call__(self, cmd, check=True, capture=False, quiet=False):
        t = cmd if isinstance(cmd, str) else " ".join(cmd)
        self.calls.append(t)
        argv = cmd.split() if isinstance(cmd, str) else list(cmd)
        if self.fail(t):
            return subprocess.CompletedProcess(cmd, 1, "", "forced failure")
        tool = self._tool(argv[0]) if argv else None
        if tool is None:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        rc, err = self.ipt(tool, argv[1:])
        if rc:
            self.errors.append((t, rc, err))
        return subprocess.CompletedProcess(cmd, rc, "", err)

    def ipt(self, tool, args):
        """One iptables command → (rc, stderr)."""
        if tool not in self.state:
            return 127, f"{tool}: command not found"
        args = list(args)
        table = "filter"
        if args[:1] == ["-t"]:
            table, args = args[1], args[2:]
        chains = self.state[tool][table]
        if not args:
            return 2, "no command"
        op, rest = args[0], args[1:]
        if op == "-N":
            if rest[0] in chains:
                return 1, f"{tool}: Chain already exists."
            chains[rest[0]] = []
            return 0, ""
        if op not in ("-A", "-I", "-D", "-C", "-F", "-X"):
            return 2, f"unknown command {op}"
        if not rest or rest[0] not in chains:
            return 1, f"{tool}: No chain/target/match by that name."
        c = rest[0]
        if op == "-F":
            chains[c] = []
            return 0, ""
        if op == "-X":
            if c in BUILTIN[table]:
                return 1, "Can't delete built-in chain"
            if chains[c]:
                return 1, "Directory not empty"
            if any(self._jump(r) == c for rules in chains.values() for r in rules):
                return 1, "Too many links"
            del chains[c]
            return 0, ""
        pos = None
        rule = rest[1:]
        if op == "-I" and rule and rule[0].isdigit():
            pos, rule = int(rule[0]) - 1, rule[1:]
        if op in ("-D", "-C"):
            if rule in chains[c]:
                if op == "-D":
                    chains[c].remove(rule)
                return 0, ""
            return 1, "Bad rule (does a matching rule exist in that chain?)."
        tgt = self._jump(rule)
        if tgt is not None and tgt not in TARGETS and tgt not in chains:
            return 2, f"Couldn't load target `{tgt}'"
        if c in BUILTIN[table]:
            if "-i" in rule and c in ("OUTPUT", "POSTROUTING"):
                return 2, f"Can't use -i with {c}"
            if "-o" in rule and c in ("INPUT", "PREROUTING"):
                return 2, f"Can't use -o with {c}"
        new = list(chains[c])
        if pos is None:
            new.append(rule)
        else:
            new.insert(min(pos, len(new)), rule)
        trial = dict(chains)
        trial[c] = new
        bad = self._valid(table, trial)
        if bad:
            return 4, EINVAL.format(bad)
        chains[c] = new
        return 0, ""

    # ---------------------------------------------------------------- queries for assertions
    def chains(self, tool="iptables", table="filter"):
        return self.state[tool][table]

    def user_chains(self, tool="iptables", table="filter"):
        return {c for c in self.state[tool][table] if c not in BUILTIN[table]} - {"DOCKER-USER"}

    def hooked(self, chain, builtin, tool="iptables", table="filter"):
        return ["-j", chain] in self.state[tool][table].get(builtin, [])
