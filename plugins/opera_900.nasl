#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21786);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-3198", "CVE-2006-3331");
  script_bugtraq_id(18594, 18692);
  script_osvdb_id(26787, 26960);

  script_name(english:"Opera < 9.00 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly contains
an issue that presents itself when the height and width parameters of
a JPEG image are set excessively high, causing Opera to allocate
insufficient memory for the image and crash as it tries to write to
memory at the wrong location. 

In addition, it is reportedly affected by a flaw that may allow an
attacker to display an SSL certificate from a trusted site on an
untrusted one." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/438074/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=834" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-49/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.00 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/22");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.00 [Bb]eta)")
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
