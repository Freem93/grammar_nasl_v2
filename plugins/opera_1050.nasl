#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44960);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-2659");
  script_bugtraq_id(36935);
  script_osvdb_id(62273, 66282);
  script_xref(name:"Secunia", value:"38546");

  script_name(english:"Opera < 10.50 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues."
  );
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.50.  Such versions are potentially affected by multiple issues :

  - An error in the TLS protocol when handling session
    re-negotiations may allow man-in-the-middle attacks. 
    (944)

  - Widget properties may be exposed to third-party domains 
    in some cases, possibly resulting in the leak of widget
    information or configuration options for the widget. 
    (959)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/944/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/959/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1050/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df8a9d78");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 50)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Opera ", version_report, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
