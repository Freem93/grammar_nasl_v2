#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19312);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-2405", "CVE-2005-2406", "CVE-2005-2407");
  script_bugtraq_id(14402, 14410, 15835);
  script_osvdb_id(18468, 18469, 19129, 21765);

  script_name(english:"Opera < 8.02 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser which is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera, an alternative web browser. 

The version of Opera installed on the remote host contains several
flaws.  One involves imaging dragging and could result in cross-site
scripting attacks and user file retrieval.  A second may let attackers
spoof the file extension in the file download dialog provided the
'Arial Unicode MS' font has been installed, which is the case with
various Microsoft Office products.  And a third is a design error in
the processing of mouse clicks in new browser windows that may be
exploited to trick a user into downloading and executing arbitrary
programs on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/15756/" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/15870/" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-19/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 8.02 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/28");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();
 
  script_summary(english:"Checks for multiple vulnerabilities in Opera < 8.02");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");
  exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-7]\.|8\.0[01]($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
