#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45437);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/25 02:11:20 $");

  script_cve_id("CVE-2010-0098", "CVE-2010-1311");
  script_bugtraq_id(39262);
  script_osvdb_id(63818, 63861);
  script_xref(name:"Secunia", value:"39329");

  script_name(english:"ClamAV < 0.96 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:
"The remote antivirus service is vulnerable to a file scan evasion
attack.");
  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.96. Such versions are reportedly affected by
multiple vulnerabilities :

  - An attacker could bypass antivirus detection by
    embedding malicious code in a specially crafted 'CAB'
    file. (1826)

  - An error in the 'qtm_decompress()' function in
    'libclamav/mspack.c' could lead to memory corruption
    when scanning a specially crafted Quantum-compressed
    file. (1771)");
  # https://github.com/vrtadmin/clamav-devel?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a1fbc11");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=1771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=1826");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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

if (ver[0] == 0 && ver[1] < 96)
{
  if (report_verbosity > 0)
  {
    report =
      '\nInstalled version : ' + version +
      '\nFixed version     : 0.96\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else exit(0, "The remote host is not affected since ClamAV version " + version + " is installed.");
