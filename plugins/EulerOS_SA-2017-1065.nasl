#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99912);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/02 13:34:10 $");

  script_cve_id(
    "CVE-2016-9634",
    "CVE-2016-9635",
    "CVE-2016-9636",
    "CVE-2016-9807",
    "CVE-2016-9808"
  );
  script_osvdb_id(
    147688,
    148101
  );

  script_name(english:"EulerOS 2.0 SP2 : gstreamer1-plugins-good (EulerOS-SA-2017-1065)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gstreamer1-plugins-good package
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Heap-based buffer overflow in the flx_decode_delta_fli
    function in gst/flx/gstflxdec.c in the FLIC decoder in
    GStreamer before 1.10.2 allows remote attackers to
    execute arbitrary code or cause a denial of service
    (application crash) by providing a 'write count' that
    goes beyond the initialized buffer.(CVE-2016-9636)

  - Heap-based buffer overflow in the flx_decode_delta_fli
    function in gst/flx/gstflxdec.c in the FLIC decoder in
    GStreamer before 1.10.2 allows remote attackers to
    execute arbitrary code or cause a denial of service
    (application crash) by providing a 'skip count' that
    goes beyond initialized buffer.(CVE-2016-9635)

  - Heap-based buffer overflow in the flx_decode_delta_fli
    function in gst/flx/gstflxdec.c in the FLIC decoder in
    GStreamer before 1.10.2 allows remote attackers to
    execute arbitrary code or cause a denial of service
    (application crash) via the start_line
    parameter.(CVE-2016-9634)

  - The FLIC decoder in GStreamer before 1.10.2 allows
    remote attackers to cause a denial of service
    (out-of-bounds write and crash) via a crafted series of
    skip and count pairs.(CVE-2016-9808)

  - The flx_decode_chunks function in gst/flx/gstflxdec.c
    in GStreamer before 1.10.2 allows remote attackers to
    cause a denial of service (invalid memory read and
    crash) via a crafted FLIC file.(CVE-2016-9807)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1065
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36437d9f");
  script_set_attribute(attribute:"solution", value:
"Update the affected gstreamer1-plugins-good packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["gstreamer1-plugins-good-1.4.5-3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer1-plugins-good");
}
