#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40801);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-2641");
  script_bugtraq_id(29908);
  script_osvdb_id(46548);
  script_xref(name:"Secunia", value:"30832");

  script_name(english:"Adobe Acrobat < 7.1.0 / 8.1.2 Unspecified JavaScript Method Handling Arbitrary Code Execution");
  script_summary(english:"Checks version of Adobe Acrobat / Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
a JavaScript parsing vulnerability."  );

  script_set_attribute(
    attribute:"description",
    value:"The version of Adobe Acrobat installed on the remote Windows host
contains a flaw in the 'Collab.collectEmailInfo()' function that may
allow a remote attacker to crash the application or to take control of
the affected system. 

To exploit this flaw, an attacker would need to trick a user on the
affected system into opening a specially crafted PDF file using the
affected application."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb08-15.html"
  );

  script_set_attribute(
    attribute:"solution",
    value: "Upgrade to Adobe Acrobat 7.1.0 / 8.1.2 with Security Update 1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute( attribute:'vuln_publication_date', value:'2008/06/23' );
  script_set_attribute( attribute:'patch_publication_date', value:'2008/06/23' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

 script_cvs_date("$Date: 2013/11/27 17:20:53 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");
  script_require_ports(139,445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

version = get_kb_item("SMB/Acrobat/Version");
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

# Regex stolen from adobe_acrobat_812.nasl
if (
  version =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))" ||
  (version =~ "^8\.1\.2($|[^0-9])" && !get_kb_item("SMB/Acrobat/812su1Installed"))
)
{
  version_ui = get_kb_item("SMB/Acrobat/Version_UI");
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item("SMB/Acrobat/Path");
    if (isnull(path)) path = "n/a";

    report = string(
      "\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 8.1.2 Security Update 1 / 7.1.0\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else 
{
  if (version =~ "^8\.1\.2($|[^0-9])" && get_kb_item("SMB/Acrobat/812su1Installed"))
    exit(0, "Acrobat "+version+" with Security Update 1 is not affected.");
  else exit(0, "Acrobat "+version+" is not affected.");
}
