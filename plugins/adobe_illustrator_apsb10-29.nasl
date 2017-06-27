#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50988);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/05/09 20:36:34 $");

  script_cve_id("CVE-2010-3152");
  script_bugtraq_id(42715);
  script_osvdb_id(67534);
  script_xref(name:"EDB-ID", value:"14773");

  script_name(english:"Adobe Illustrator Path Subversion Arbitrary DLL Injection Code Execution (APSB10-29)");
  script_summary(english:"Checks app's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Illustrator installed on the remote host is
earlier than 15.0.2.  Such versions insecurely look in their current
working directory when resolving DLL and file dependencies, such as
for 'aires.dll'. 

If a malicious DLL with the same name as a required DLL is located in
the application's current working directory, the malicious DLL will be
loaded."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-29.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Illustrator CS5 if necessary and apply the 15.0.2
update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:illustrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Adobe Illustrator/version");
path = get_kb_item_or_exit("SMB/Adobe Illustrator/path");
prod = get_kb_item_or_exit("SMB/Adobe Illustrator/product");


fixed_version = "15.0.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product           : ' + prod + 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port, extra:report);
  exit(0);
}
else exit(0, "The host is not affected since Adobe Illustrator " + version + " is installed.");
