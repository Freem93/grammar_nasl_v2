#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44045);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2014/04/17 18:47:27 $");

  script_bugtraq_id(37753);
  script_xref(name:"CERT", value:"204889");
  script_xref(name:"Secunia", value:"27105");

  script_name(english:"MS KB979267: Flash 6 ActiveX Control On Windows XP Multiple Vulnerabilities");
  script_summary(english:"Checks if the Flash 6 control is installed on an XP host");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Flash ActiveX control installed on the remote Windows host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Macromedia Flash Player 6 ActiveX control that comes bundled with
Windows XP is installed on the remote host.  This version has multiple
memory corruption vulnerabilities.

By tricking a user into viewing a specially crafted web page, a remote
attacker may be able to exploit these issues to execute arbitrary code
on the affected host subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2007-77/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/979267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blogs.adobe.com/psirt/2010/01/microsoft_security_advisory_97.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?602edd75"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Either remove the Flash Player ActiveX control or install the latest
version of Flash from Adobe."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/12");
  # no patch...solution -> uninstall or upgrade
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macromedia:flash");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


# Flash 6 was only included with XP
if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if (hotfix_check_sp(xp:4) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The registry wasn't enumerated.");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';
port = kb_smb_transport();

file = activex_get_filename(clsid:clsid);
if (file)
{
  version = activex_get_fileversion(clsid:clsid);
  ver = split(version, sep:'.', keep:FALSE);

  if (!isnull(version) && ver[0] == "6")
  {
    report =
      '\n  Class identifier  : '+clsid+
      '\n  Filename          : '+file+
      '\n  Installed version : '+version+'\n';

    if (report_paranoia > 1)
    {
      report +=
        '\n'+
        'Note, though, that Nessus did not check whether the kill bit was\n'+
        'set for the control\'s CLSID because of the Report Paranoia setting\n'+
        'in effect when this scan was run.\n';
    }
    else
    {
      killbit = activex_get_killbit(clsid:clsid);
      report +=
        '\n'+
        'Moreover, its kill bit is not set so it is accessible via Internet\n'+
        'Explorer.\n';
    }

    # Only report if we're running as paranoid, or the kill bit isn't set
    if (report_paranoia > 1 || killbit == 0)
    {
      if (report_verbosity > 0)
        security_hole(port:port, extra:report);
      else
        security_hole(port);

      activex_end();
      exit(0);
    }
  }
}

activex_end();

if (isnull(file)) exit(1, "activex_get_filename() returned NULL.");
if (strlen(file) == 0) exit(0, "The control is not installed (class id '"+clsid+"' not found).");
if (isnull(version)) exit(1, "Failed to get file version of '"+file+"'.");
if (killbit == 1) exit(0, file + " is vulnerable, but the kill bit is set.");
exit(0, "The control is not affected since its version is "+version+".");

