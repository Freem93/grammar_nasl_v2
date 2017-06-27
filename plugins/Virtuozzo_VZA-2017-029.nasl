#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99599);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id(
    "CVE-2016-9793",
    "CVE-2017-5986",
    "CVE-2017-6353",
    "CVE-2017-7472"
  );
  script_osvdb_id(
    148409,
    152094,
    152685,
    155922
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2017-029)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - It was found that keyctl_set_reqkey_keyring() function
    leaked thread keyring which could allow an unprivileged
    local user to exhaust kernel memory.

  - net/sctp/socket.c in the Linux kernel through 4.10.1
    did not properly restrict association peel-off
    operations during certain wait states, which allowed
    local users to cause a denial of service (invalid
    unlock and double free) via a multithreaded
    application.

  - Race condition in the sctp_wait_for_sndbuf function in
    net/sctp/socket.c in the Linux kernel before 4.9.11
    could allow local users to cause a denial of service
    (assertion failure and panic) via a multithreaded
    application that peeled off an association in a certain
    buffer-full state.

  - Andrey Konovalov discovered that signed integer
    overflows existed in the setsockopt() system call when
    handling the SO_SNDBUFFORCE and SO_RCVBUFFORCE options.
    A local attacker with the CAP_NET_ADMIN capability
    could use this to cause a denial of service (system
    crash or memory corruption).

  - A vulnerability was discovered in the handling of pid
    namespaces in the kernel. A privileged user inside a
    container could trigger a kernel crash (NULL pointer
    dereference in proc_flush_task()) using a sequence of
    system calls including wait4().

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2792896");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-15.2-19.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93e4e6f8");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-18.7-19.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf94943");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-20.18-19.1-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1472b55");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list", "Host/readykernel-info");

  exit(0);
}

include("global_settings.inc");
include("readykernel.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = eregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

rk_info = get_kb_item("Host/readykernel-info");
if (empty_or_null(rk_info)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");

checks = make_list2(
  make_array(
    "kernel","vzkernel-3.10.0-327.18.2.vz7.15.2",
    "patch","readykernel-patch-15.2-19.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.36.1.vz7.18.7",
    "patch","readykernel-patch-18.7-19.1-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-327.36.1.vz7.20.18",
    "patch","readykernel-patch-20.18-19.1-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_HOLE, release:"Virtuozzo-7");
