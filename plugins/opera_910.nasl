#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23977);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-0126", "CVE-2007-0127");
  script_bugtraq_id(21882);
  script_osvdb_id(31574, 31575);

  script_name(english:"Opera < 9.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly contains
a heap overflow vulnerability that can be triggered when processing
the DHT marker in a specially crafted JPEG image to crash the browser
or possibly allow execution of arbitrary code on the affected host. 

In addition, another flaw in Opera's createSVGTransformFromMatrix
object typecasting may lead to a browser crash or arbitrary code
execution if support for JavaScript is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e804d36" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1770d0e0" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456053" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456066" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=851" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=852" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94, 119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/05");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/01/05");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^9\.0[0-9]($|[^0-9])")
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
