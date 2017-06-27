#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19766);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-3006", "CVE-2005-3007", "CVE-2005-3041");
  script_bugtraq_id(14880, 14884);
  script_osvdb_id(19508, 19509, 20003);

  script_name(english:"Opera < 8.50 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser which is vulnerable to
attachment spoofing, script insertion and unintentional file uploads." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera, an alternative web browser. 

The installed version of Opera on the remote host contains two flaws
its mail client and one in the browser.  First, message attachments
are opened from the user's cache directory without any warnings, which
can be exploited to execute arbitrary JavaScript within the context of
'file://'.  Second, appending an additional '.' to an attachment's
filename causes the file type to be spoofed.  And third, the browser
is affected by an unspecified drag-and-drop vulnerability that
facilitates unintentional file uploads." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-42/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/850/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 8.50 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/20");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();
 
  script_summary(english:"Checks for multiple vulnerabilities in Opera < 8.50");
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

if (version_ui =~ "^([0-7]\.|8\.[0-4][0-9]($|[^0-9]))")
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
