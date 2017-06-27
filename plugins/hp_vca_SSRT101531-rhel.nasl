#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77022);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"HP", value:"emr_na-c04262472");
  script_xref(name:"HP", value:"HPSBMU03020");
  script_xref(name:"HP", value:"SSRT101531");

  script_name(english:"HP Version Control Agent (VCA) Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the version of the VCA package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The RPM installation of HP Version Control Agent (VCA) on the remote
Linux host is version 7.2.2, 7.3.0, or 7.3.1. It is, therefore,
affected by an information disclosure vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.");
  script_set_attribute(attribute:"solution", value:"Upgrade to VCA 7.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04262472
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9ffb6dc");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_agent");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "ppc" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

# These are the only versions the software is supported
# however you can install it on later versions. So
# only check non-supported versions if paranoia is on.
if (
  report_paranoia < 2 &&
  !ereg(pattern:"release [3-6]($|[^0-9])", string:release)
) audit(AUDIT_OS_NOT, "Red Hat 3 / 4 / 5 / 6");

rpms = get_kb_item_or_exit("Host/RedHat/rpm-list");
if ("hpvca-" >!< rpms) audit(AUDIT_PACKAGE_NOT_INSTALLED, "HP Version Control Agent");

# Get the RPM version
match = eregmatch(string:rpms, pattern:"(^|\n)hpvca-(\d+\.\d+\.\d+-\d+)");
if (isnull(match)) audit(AUDIT_VER_FAIL,"HP Version Control Agent");

version = match[2];
version = ereg_replace(string:version, replace:".", pattern:"-");

fix = "7.3.2.0";

# These specific version lines are affected
if (
  version =~ "^7\.2\.2\." ||
  version =~ "^7\.3\.[0-1]\."
)
{
  if (report_verbosity > 0)
  {
    report =
     '\n  Installed version : ' + version +
     '\n  Fixed version     : ' + fix +
     '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "HP Version Control Agent");
