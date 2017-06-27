#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31129);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-1080", "CVE-2008-1081", "CVE-2008-1082");
  script_bugtraq_id(27901);
  script_osvdb_id(42696, 42697, 42698);
  script_xref(name:"Secunia", value:"29029");

  script_name(english:"Opera < 9.26 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly is
affected by several issues :

  - Simulated text input could trick users into 
    uploading arbitrary files.

  - Image properties comments containing script will
    be run when displaying the image properties, 
    leading to code execution in the wrong security 
    context.

  - Representation of DOM attribute values could allow
    cross-site scripting when importing XML into a 
    document." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/877/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/879/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/880/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/926/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.26 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 79, 94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/20");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[0-5])($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
