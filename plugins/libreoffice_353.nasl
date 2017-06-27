#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59180);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/07/12 01:44:40 $");

  script_cve_id("CVE-2012-1149", "CVE-2012-2334");
  script_bugtraq_id(53142, 53570);
  script_osvdb_id(81202, 81988, 82517);
  script_xref(name:"EDB-ID", value:"18754");

  script_name(english:"LibreOffice < 3.5.3 Multiple Memory Corruption Vulnerabilities");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application affected by multiple memory
corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of LibreOffice prior to 3.5.3 is installed on the remote
Windows host. It is, therefore, reportedly affected by multiple memory 
corruption vulnerabilities :

  - An integer overflow vulnerability exists in the 
    graphics object loading code that could allow a remote
    attacker to execute arbitrary code or cause an 
    application crash. (CVE-2012-1149)

  - A denial of service vulnerability exists in the 
    PowerPoint presentation import code. (CVE-2012-2334)

  - A memory corruption vulnerability in the code for
    handling .RTF files."
  );
  script_set_attribute(attribute:"see_also", value:"http://shinnai.altervista.org/exploits/SH-016-20120416.html");
  # http://blog.documentfoundation.org/2012/05/02/the-document-foundation-announces-libreoffice-3-5-3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79f70016");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 3.5.3 or greater.");
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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("SMB/LibreOffice/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/LibreOffice";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI");

if (
  # nb: first release of LibreOffice was 3.3.0.
  version =~ "^3\.[3-4]\." ||
  (version =~ "^3\.5\." && ver_compare(ver:version, fix:'3.5.3.2', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : 3.5.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The LibreOffice "+version_ui+" install under "+path+" is not affected.");
