#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59181);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/18 10:51:14 $");

  script_bugtraq_id(53142);
  script_osvdb_id(81202);
  script_xref(name:"EDB-ID", value:"18754");

  script_name(english:"LibreOffice < 3.5.3 RTF File Handling Remote Memory Corruption (Mac OS X)");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application affected by a memory
corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of LibreOffice prior to 3.5.3 is installed on the remote
Mac OS X host.  It thus is reportedly affected by a memory corruption
vulnerability in its handling of RTF files. 

By tricking a victim into opening a specially crafted RTF file, a
remote attacker may be able to execute arbitrary code on the host
subject to the privileges of the user running the affected
application."
  );
  script_set_attribute(attribute:"see_also", value:"http://shinnai.altervista.org/exploits/SH-016-20120416.html");
  # http://blog.documentfoundation.org/2012/05/02/the-document-foundation-announces-libreoffice-3-5-3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79f70016");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 3.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("MacOSX/LibreOffice/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/LibreOffice";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  # nb: first release of LibreOffice was 3.3.0.
  ver[0] == 3 &&
  (
    ver[1] < 5 ||
    (ver[1] == 5 && ver[2] < 3)  # < 3.5.3
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.3\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The LibreOffice "+version+" install under "+path+" is not affected.");
