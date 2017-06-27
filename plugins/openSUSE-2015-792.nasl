#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-792.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87017);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/11/24 14:17:20 $");

  script_cve_id("CVE-2014-8178", "CVE-2014-8179");

  script_name(english:"openSUSE Security Update : docker (openSUSE-2015-792)");
  script_summary(english:"Check for the openSUSE-2015-792 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Docker was updated to version 1.9.0, bringing features and bugfixes
(bnc#954812) :

  - Runtime :

  - `docker stats` now returns block IO metrics (#15005)

  - `docker stats` now details network stats per interface
    (#15786)

  - Add `ancestor=<image>` filter to `docker ps --filter`
    flag to filter containers based on their ancestor images
    (#14570)

  - Add `label=<somelabel>` filter to `docker ps --filter`
    to filter containers based on label (#16530)

  - Add `--kernel-memory` flag to `docker run` (#14006)

  - Add `--message` flag to `docker import` allowing to
    specify an optional message (#15711)

  - Add `--privileged` flag to `docker exec` (#14113)

  - Add `--stop-signal` flag to `docker run` allowing to
    replace the container process stopping signal (#15307)

  - Add a new `unless-stopped` restart policy (#15348)

  - Inspecting an image now returns tags (#13185)

  - Add container size information to `docker inspect`
    (#15796)

  - Add `RepoTags` and `RepoDigests` field to
    `/images/{name:.*}/json` (#17275)

  - Remove the deprecated `/container/ps` endpoint from the
    API (#15972)

  - Send and document correct HTTP codes for
    `/exec/<name>/start` (#16250)

  - Share shm and mqueue between containers sharing IPC
    namespace (#15862)

  - Event stream now shows OOM status when
    `--oom-kill-disable` is set (#16235)

  - Ensure special network files (/etc/hosts etc.) are
    read-only if bind-mounted with `ro` option (#14965)

  - Improve `rmi` performance (#16890)

  - Do not update /etc/hosts for the default bridge network,
    except for links (#17325)

  - Fix conflict with duplicate container names (#17389)

  - Fix an issue with incorrect template execution in
    `docker inspect` (#17284)

  - DEPRECATE `-c` short flag variant for `--cpu-shares` in
    docker run (#16271)

  - Client :

  - Allow `docker import` to import from local files
    (#11907)

  - Builder :

  - Add a `STOPSIGNAL` Dockerfile instruction allowing to
    set a different stop-signal for the container process
    (#15307)

  - Add an `ARG` Dockerfile instruction and a `--build-arg`
    flag to `docker build` that allows to add build-time
    environment variables (#15182)

  - Improve cache miss performance (#16890)

  - Storage :

  - devicemapper: Implement deferred deletion capability
    (#16381)

  - Networking :

  - `docker network` exits experimental and is part of
    standard release (#16645)

  - New network top-level concept, with associated
    subcommands and API (#16645) WARNING: the API is
    different from the experimental API

  - Support for multiple isolated/micro-segmented networks
    (#16645)

  - Built-in multihost networking using VXLAN based overlay
    driver (#14071)

  - Support for third-party network plugins (#13424)

  - Ability to dynamically connect containers to multiple
    networks (#16645)

  - Support for user-defined IP address management via
    pluggable IPAM drivers (#16910)

  - Add daemon flags `--cluster-store` and
    `--cluster-advertise` for built-in nodes discovery
    (#16229)

  - Add `--cluster-store-opt` for setting up TLS settings
    (#16644)

  - Add `--dns-opt` to the daemon (#16031)

  - DEPRECATE following container `NetworkSettings` fields
    in API v1.21: `EndpointID`, `Gateway`,
    `GlobalIPv6Address`, `GlobalIPv6PrefixLen`, `IPAddress`,
    `IPPrefixLen`, `IPv6Gateway` and `MacAddress`. Those are
    now specific to the `bridge` network. Use
    `NetworkSettings.Networks` to inspect the networking
    settings of a container per network.

  - Volumes :

  - New top-level `volume` subcommand and API (#14242)

  - Move API volume driver settings to host-specific config
    (#15798)

  - Print an error message if volume name is not unique
    (#16009)

  - Ensure volumes created from Dockerfiles always use the
    local volume driver (#15507)

  - DEPRECATE auto-creating missing host paths for bind
    mounts (#16349)

  - Logging :

  - Add `awslogs` logging driver for Amazon CloudWatch
    (#15495)

  - Add generic `tag` log option to allow customizing
    container/image information passed to driver (e.g. show
    container names) (#15384)

  - Implement the `docker logs` endpoint for the journald
    driver (#13707)

  - DEPRECATE driver-specific log tags (e.g. `syslog-tag`,
    etc.) (#15384)

  - Distribution :

  - `docker search` now works with partial names (#16509)

  - Push optimization: avoid buffering to file (#15493)

  - The daemon will display progress for images that were
    already being pulled by another client (#15489)

  - Only permissions required for the current action being
    performed are requested (#)

  - Renaming trust keys (and respective environment
    variables) from `offline` to `root` and `tagging` to
    `repository` (#16894)

  - DEPRECATE trust key environment variables
    `DOCKER_CONTENT_TRUST_OFFLINE_PASSPHRASE` and
    `DOCKER_CONTENT_TRUST_TAGGING_PASSPHRASE` (#16894)

  - Security :

  - Add SELinux profiles to the rpm package (#15832)

  - Fix various issues with AppArmor profiles provided in
    the deb package (#14609)

  - Add AppArmor policy that prevents writing to /proc
    (#15571)

  - Change systemd unit file to no longer use the deprecated
    '-d' option (bnc#954737)

  - Also docker was updated to the 1.8.3 version that fixes
    security issues :

  - Fix layer IDs lead to local graph poisoning
    (CVE-2014-8178) (bnc#949660)

  - Fix manifest validation and parsing logic errors allow
    pull-by-digest validation bypass (CVE-2014-8179)

  - Add `--disable-legacy-registry` to prevent a daemon from
    using a v1 registry"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"docker-1.9.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-bash-completion-1.9.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-debuginfo-1.9.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-debugsource-1.9.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-test-1.9.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-zsh-completion-1.9.0-4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-bash-completion / docker-debuginfo / etc");
}
