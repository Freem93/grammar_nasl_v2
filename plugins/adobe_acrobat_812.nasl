#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40800);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    #"CVE-2007-4768",  heap overflow in PCRE library
    "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655",
    "CVE-2008-0667", "CVE-2008-0726", "CVE-2008-2042");
  script_bugtraq_id(27641);
  script_osvdb_id(41492, 41493, 41494, 41495, 42683, 44998, 46549);

  script_name(english:"Adobe Acrobat < 8.1.2 / 7.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities."  );

   script_set_attribute(
      attribute:"description",
      value:"The version of Adobe Acrobat installed on the remote host is earlier
than 8.1.2 or 7.1.0.  Such versions are reportedly affected by
multiple vulnerabilities :

  - A design error vulnerability may allow an attacker to
    gain control of a user's printer.

  - Multiple stack-based buffer overflows may allow an
    attacker to execute arbitrary code subject to the
    user's privileges.

  - Insecure loading of 'Security Provider' libraries may
    allow for arbitrary code execution.

  - An insecure method exposed by the JavaScript library
    in the 'EScript.api' plug-in allows direct control
    over low-level features of the object, which allows
    for execution of arbitrary code as the current user.

  - Two vulnerabilities in the unpublicized function
    'app.checkForUpdate()' exploited through a callback
    function could lead to arbitrary code execution in
    Adobe Acrobat 7."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa08-01.html"
    );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb08-13.html"
  );

  script_set_attribute(
    attribute:"solution",
    value: "Upgrade to Adobe Acrobat 8.1.2 / 7.1.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.collectEmailInfo() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94, 119, 189, 399);

  script_set_attribute( attribute:'vuln_publication_date', value:'2008/02/07' );
  script_set_attribute( attribute:'patch_publication_date', value:'2008/05/16' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

 script_cvs_date("$Date: 2016/11/11 19:58:27 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");

  exit(0);
}

#

include("global_settings.inc");


version = get_kb_item("SMB/Acrobat/Version");
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

if (version =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))")
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
      "  Fix               : 8.1.2 / 7.1.0\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");
