#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58662);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2012-1182");
  script_bugtraq_id(52973);
  script_osvdb_id(81303);
  script_xref(name:"ZDI", value:"ZDI-12-061");
  script_xref(name:"ZDI", value:"ZDI-12-062");
  script_xref(name:"ZDI", value:"ZDI-12-063");
  script_xref(name:"ZDI", value:"ZDI-12-064");
  script_xref(name:"ZDI", value:"ZDI-12-068");
  script_xref(name:"ZDI", value:"ZDI-12-069");
  script_xref(name:"ZDI", value:"ZDI-12-070");
  script_xref(name:"ZDI", value:"ZDI-12-071");
  script_xref(name:"ZDI", value:"ZDI-12-072");

  script_name(english:"Samba 3.x < 3.6.4 / 3.5.14 / 3.4.16 RPC Multiple Buffer Overflows");
  script_summary(english:"Checks version of Samba");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple buffer overflow
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.x running on the
remote host is earlier than 3.6.4 / 3.5.14 / 3.4.16.  It is,
therefore, affected by multiple heap-based buffer overflow
vulnerabilities. 

An error in the DCE/RPC IDL (PIDL) compiler causes the RPC handling
code it generates to contain multiple heap-based buffer overflow
vulnerabilities.  This generated code can allow a remote,
unauthenticated attacker to use malicious RPC calls to crash the
application and possibly execute arbitrary code as the root user. 

Note that Nessus has not actually tried to exploit this issue or
otherwise determine if one of the associated patches has been
applied.");
  script_set_attribute(attribute:"solution", value:
"Either install the appropriate patch referenced in the project's
advisory or upgrade to 3.6.4 / 3.5.14 / 3.4.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-061/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-062/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-063/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-064/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-069/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-070/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-071/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-072/");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2012-1182.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.4.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.4.16.html");
  # Patch links
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/security.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("SMB/transport");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Patches have been released for 3.x < 3.4, but 
# those patches do not change the version number
if (
  (ver[0] == 3 && ver[1] < 4) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 16) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 14) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version + 
             '\n  Fixed version      : 3.6.4 / 3.5.14 / 3.4.16\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Samba", version);
