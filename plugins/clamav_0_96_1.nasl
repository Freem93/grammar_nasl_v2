#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46706);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2010-1639", "CVE-2010-1640");
  script_bugtraq_id(40317, 40318);
  script_osvdb_id(64774, 64940);
  script_xref(name:"Secunia", value:"39895");

  script_name(english:"ClamAV < 0.96.1 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:
"The remote antivirus service is affected by multiple denial of service
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.96.1. Such versions are reportedly affected by
multiple vulnerabilities :

  - An error exists within the 'cli_pdf()' function in
    'libclamav/pdf.c' when processing certain PDF files.
    (Bug 2016)

  - An error exists within the 'parseicon()' function in
    'libclamav/pe_icons.c' when processing PE icons.  This
    can be exploited to trigger an out-of-bounds access when
    reading data and potentially cause a crash via a
    specially crafted PE file. (Bug 2031)");
  # https://github.com/vrtadmin/clamav-devel?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cd93f30");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2031");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.96.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb. banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item("Antivirus/ClamAV/version");
if (!version) exit(1, "The 'Antivirus/ClamAV/version' KB item is missing.");

port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 0 &&
  (
    ver[1] < 96 ||
    (
      ver[1] == 96 &&
      (isnull(ver[2]) || ver[2] < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.96.1 \n';
    security_warning(port:port, extra:report);
  }
}
else exit(0, "The remote host is not affected since ClamAV version " + version + " is installed.");
