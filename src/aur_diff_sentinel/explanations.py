from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    what: str
    why: str
    inspect: str
    summary: str = ""


def reason_phrase(rule_id: str, fallback: str) -> str:
    explanation = EXPLANATIONS.get(rule_id)
    if explanation is not None and explanation.summary:
        return explanation.summary
    return fallback


EXPLANATIONS: dict[str, Explanation] = {
    # -- rules.py --
    "eval-used": Explanation(
        what="The PKGBUILD uses the eval command to execute dynamically generated shell code.",
        why="eval can execute code constructed from variables or downloaded content, making review harder.",
        inspect="Review what input feeds into eval and whether it can be controlled by external sources.",
        summary="eval used",
    ),
    "curl-pipe-shell": Explanation(
        what="A remote download (curl or wget) is piped directly into a shell.",
        why="Executing downloaded content directly bypasses normal source review and verification.",
        inspect="Check what is being downloaded and whether it should be declared in source=() instead.",
        summary="remote download piped to shell",
    ),
    "setuid-permission": Explanation(
        what="A file is being installed with setuid or setgid permission bits.",
        why="Setuid files execute with elevated privileges and are a common target for exploitation.",
        inspect="Verify that the setuid binary is expected, necessary, and comes from a trusted source.",
        summary="setuid/setgid permission",
    ),
    "privilege-command": Explanation(
        what="A command that modifies users, services, or the live system was detected.",
        why="PKGBUILDs should normally stage files under $pkgdir, not modify the live system directly.",
        inspect="Check why the command needs to modify the live system and whether it can be avoided.",
        summary="live-system command",
    ),
    "install-script": Explanation(
        what="The PKGBUILD references an install script file via the install= variable.",
        why="Install scripts can execute commands during package installation, upgrade, or removal on the live system.",
        inspect="Review the install script for commands that modify the live system or fetch external resources.",
        summary="install script referenced",
    ),
    "pacman-hook-exec": Explanation(
        what="A pacman hook contains an Exec= action that runs during package transactions.",
        why="Pacman hooks run automatically and can execute arbitrary commands on the live system.",
        inspect="Review the hook action for commands that fetch, install, or modify system state.",
        summary="pacman hook action",
    ),
    "shell-c": Explanation(
        what="sh -c or bash -c is used to execute a dynamically constructed command.",
        why="Dynamic shell execution can hide complex or generated command sequences from review.",
        inspect="Check what command string is being executed and whether it depends on external input.",
        summary="dynamic shell execution",
    ),
    "source-command": Explanation(
        what="A file is being sourced into the current shell context.",
        why="Sourcing a file executes all its content in the current shell, which can change variables and behavior.",
        inspect="Review the sourced file to understand what it sets or executes.",
        summary="shell source command",
    ),
    "decoded-pipe-shell": Explanation(
        what="Decoded content (base64, xxd, or openssl) is piped directly into a shell.",
        why="Decoding and executing content can hide malicious commands from casual inspection.",
        inspect="Examine what is being decoded and why it cannot be written as readable script code.",
        summary="decoded content piped into shell",
    ),
    "inline-interpreter-command": Explanation(
        what="An inline interpreter command (python -c, perl -e, awk system) was detected.",
        why="Inline interpreter commands can hide meaningful behavior in compact, hard-to-read code.",
        inspect="Expand the inline command to understand its full behavior and dependencies.",
        summary="inline interpreter command",
    ),
    "scriptlet-package-manager": Explanation(
        what="A package manager command runs inside an install script or pacman hook.",
        why="Package-manager commands in install scripts run on the live system and can download and execute code.",
        inspect="Review what packages are being installed and whether they are expected dependencies.",
        summary="package manager in live script",
    ),
    "direct-exec-package-manager": Explanation(
        what="A command such as npx, bunx, or pnpm exec can fetch and execute code directly.",
        why="Direct-exec package managers download and run code without explicit installation, making review harder.",
        inspect="Check what packages or scripts are being executed and whether they should be declared as dependencies.",
        summary="package manager direct execution",
    ),
    "network-in-build": Explanation(
        what="Network activity was detected inside a build function.",
        why="PKGBUILDs should normally declare downloaded inputs in source=() so makepkg can verify them.",
        inspect="Check whether the network access can be replaced with a source=() entry and checksum verification.",
        summary="network activity during build",
    ),
    "writes-outside-pkgdir": Explanation(
        what="A command may write files outside the $pkgdir staging directory.",
        why="Package files should be staged under $pkgdir so makepkg can track and package them correctly.",
        inspect="Verify that all file writes target $pkgdir-based paths, not live-system paths like /usr or /etc.",
        summary="write outside pkgdir",
    ),
    # -- pkgbuild_analysis.py --
    "checksum-skip": Explanation(
        what="Checksum verification was skipped for one or more sources.",
        why="Skipping checksums removes verification that downloaded sources match what the author intended.",
        inspect="Check whether the skipped checksum corresponds to a VCS source or a downloaded archive.",
        summary="checksum verification skipped",
    ),
    # -- source_checksum_diff.py --
    "source-url-added": Explanation(
        what="A new source URL was added to the PKGBUILD.",
        why="New source URLs expand the package's supply chain and should be reviewed before updating.",
        inspect="Verify that the new source URL is expected, official, and consistent with upstream releases.",
        summary="source URL added",
    ),
    "https-to-http-downgrade": Explanation(
        what="A source URL changed from HTTPS to HTTP.",
        why="Downgrading transport security exposes downloads to interception and modification.",
        inspect="Verify that the HTTP URL is intentional and that the source can be verified through other means.",
        summary="HTTPS changed to HTTP",
    ),
    "source-domain-changed": Explanation(
        what="The package source moved from one domain to another.",
        why="A changed source host can indicate a meaningful upstream or supply-chain change.",
        inspect="Verify that the new domain is expected, official, and consistent with upstream release notes.",
        summary="source domain changed",
    ),
    "checksum-array-removed": Explanation(
        what="An entire checksum array was removed from the PKGBUILD.",
        why="Removing checksums eliminates source verification and should be reviewed carefully.",
        inspect="Check why checksums were removed and whether sources are still verifiable.",
        summary="checksum array removed",
    ),
    "checksum-algorithm-weakened": Explanation(
        what="The checksum algorithm was changed to a weaker alternative.",
        why="Weaker checksum algorithms reduce confidence in source integrity verification.",
        inspect="Check whether the algorithm change is intentional and whether stronger verification is possible.",
        summary="checksum algorithm weakened",
    ),
    "checksum-count-mismatch": Explanation(
        what="The number of source entries and checksum entries does not match.",
        why="Each source should normally have a matching checksum. A mismatch may indicate an incomplete update.",
        inspect="Verify that every source entry has a corresponding checksum or that the mismatch is intentional.",
        summary="source/checksum count mismatch",
    ),
    "checksum-skip-added": Explanation(
        what="A checksum SKIP was newly added where a real checksum existed before.",
        why="Newly skipping checksums weakens source verification compared to the previous version.",
        inspect="Check whether the new SKIP corresponds to a VCS source or a newly added unverifiable download.",
        summary="checksum SKIP added",
    ),
    # -- metadata_diff.py --
    "install-script-added": Explanation(
        what="A new install script file was added to the package metadata.",
        why="Install scripts run on the live system during install, upgrade, or removal.",
        inspect="Review the new install script for commands that modify the live system or fetch external resources.",
        summary="install script added",
    ),
    "pacman-hook-added": Explanation(
        what="A new pacman hook file was added to the package metadata.",
        why="Pacman hooks run automatically during package transactions and can execute arbitrary commands.",
        inspect="Review the hook actions for commands that fetch, install, or modify system state.",
        summary="pacman hook added",
    ),
    "aur-metadata-executable-added": Explanation(
        what="A new executable script file was added to the AUR metadata.",
        why="Executable scripts committed to AUR metadata should be reviewed before updating.",
        inspect="Read the new script to understand its purpose and what commands it executes.",
        summary="executable metadata file added",
    ),
    "aur-metadata-elf-added": Explanation(
        what="A compiled ELF binary was added directly to the AUR metadata.",
        why="Compiled binaries committed directly to AUR metadata are unusual and should be reviewed carefully.",
        inspect="Verify that the binary is expected, trusted, and cannot be replaced with a build-from-source approach.",
        summary="ELF metadata file added",
    ),
    # -- dependency_diff.py --
    "dependency-added": Explanation(
        what="A new dependency was added to the package.",
        why="New dependencies expand the package's trust boundary and should be reviewed.",
        inspect="Check whether the new dependency is expected and whether it changes the package's dependency surface.",
        summary="new dependency added",
    ),
    "javascript-tooling-dependency-added": Explanation(
        what="A JavaScript tooling dependency (npm, nodejs, bun, etc.) was added.",
        why="JavaScript tooling can fetch and execute code from remote registries during builds.",
        inspect="Review whether the tooling dependency is necessary and whether it is combined with install scripts or hooks.",
        summary="JavaScript tooling dependency added",
    ),
    "build-tool-dependency-added": Explanation(
        what="A build-tool dependency that can fetch or execute external code was added.",
        why="Build tools such as cargo, pip, and go can download and execute code from remote registries.",
        inspect="Check whether the build tool is expected and whether its network activity is contained.",
        summary="build-tool dependency added",
    ),
    "aur-dependency-added": Explanation(
        what="A new dependency appears to be an AUR package rather than an official repository package.",
        why="AUR dependencies expand the trust boundary further than official repository dependencies.",
        inspect="Review the AUR dependency's own PKGBUILD and maintenance history before updating.",
        summary="AUR dependency added",
    ),
    "dependency-moved": Explanation(
        what="An existing dependency moved between dependency groups.",
        why="Moving a dependency from makedepends to depends, for example, changes when it is needed.",
        inspect="Check whether the group change matches the dependency's actual role in the package.",
        summary="dependency moved",
    ),
    "dependency-removed": Explanation(
        what="A dependency was removed from the package.",
        why="Removed dependencies may be normal packaging churn, but can change review context.",
        inspect="Check whether the removed dependency is still expected or whether its removal is intentional.",
        summary="dependency removed",
    ),
    # -- correlation.py --
    "temporary-directory-package-install": Explanation(
        what="A package manager runs from a temporary directory inside an install script or hook.",
        why="Installing packages from /tmp in an install script runs on the live system.",
        inspect="Review what packages are being installed and why the temporary directory is used.",
        summary="package install from temporary directory",
    ),
    "suspicious-live-install-sequence": Explanation(
        what="Multiple signals combine: new JS tooling dependency, install script or hook, temporary directory, and package-manager command.",
        why="This combination can indicate a supply-chain attack pattern seen in real AUR incidents.",
        inspect="Review the entire update diff. Check the install script, the new dependency, and the package-manager command together.",
        summary="combined live install sequence",
    ),
    "dependency-with-risk-signals": Explanation(
        what="New dependencies appeared together with other high-risk signals.",
        why="Combined changes increase review complexity and may indicate a coordinated update.",
        inspect="Review new dependencies together with the other detected changes as a combined set.",
        summary="dependency combined with high-risk signals",
    ),
}
