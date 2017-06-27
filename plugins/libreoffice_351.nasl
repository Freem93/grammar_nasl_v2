#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58726);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/02 15:06:43 $");

  script_cve_id("CVE-2012-0037");
  script_bugtraq_id(52681);
  script_osvdb_id(80307);

  script_name(english:"LibreOffice < 3.4.6 / 3.5.1 XML External Entity RDF Document Handling Information Disclosure");
  script_summary(english:"Checks if patch is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an application affected by a data leakage
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of LibreOffice < 3.4.6 / 3.5.1
that has flaws in the way certain XML components are processed for
external entities in ODF documents.  These flaws can be utilized to
access and inject the content of local files into an ODF document
without a user's knowledge or permission, or inject arbitrary code
that would be executed when opened by the user."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/advisories/CVE-2012-0037/");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to LibreOffice 3.4.6 / 3.5.1 or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
  version =~ "^3\.3\." ||
  (version =~ "^3\.4\." &&
   ver_compare(ver:version, fix:'3.4.602.500', strict:FALSE) == -1)
  ||
  (version =~ "^3\.5\." &&
   ver_compare(ver:version, fix:'3.5.0.102', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : 3.4.6 / 3.5.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The LibreOffice "+version_ui+" install under "+path+" is not affected.");
