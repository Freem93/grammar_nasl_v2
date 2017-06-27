#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(46351);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/08/20 16:45:02 $");

 script_cve_id("CVE-2010-1635", "CVE-2010-1642");
 script_bugtraq_id(40097);
 script_osvdb_id(65435, 65436);

 script_name(english:"Samba < 3.4.8 / 3.5.2 Session Setup AndX DoS");
 script_summary(english:"Checks version of Samba");

 script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to denial of service attacks.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba installed on the remote
host is a version of 3.4 before 3.4.8 or 3.5 < 3.5.2. Such versions
are affected by two denial of service vulnerabilities that can be
triggered via either a NULL pointer dereference or an uninitialized
variable read.

By sending specially crafted 'Session Setup AndX' requests, an
unauthenticated, remote attacker can exploit these vulnerabilities to
crash the affected service, thereby denying service to legitimate
users.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.4.8 / 3.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66795feb");
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7229");
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7254");
 script_set_attribute(attribute:"see_also", value:"http://samba.org/samba/history/samba-3.4.8.html");
 script_set_attribute(attribute:"see_also", value:"http://samba.org/samba/history/samba-3.5.2.html");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman)) exit(1, "The 'SMB/NativeLanManager' KB item is missing.");
if ("Samba " >!< lanman) exit(1, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);

for (i=0; i<max_index(ver); i++)
{
  ver[i] = int(ver[i]);
}

if (
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 8) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 2)
)
{
  if (report_verbosity > 1)
  {
    report = '\n' +
      'The remote Samba server appears to be :\n' +
      '\n' +
      '  ' + lanman + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'Samba version '+lanman+' is listening on port "+port+" and not affected.');
