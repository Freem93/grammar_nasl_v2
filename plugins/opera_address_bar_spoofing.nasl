#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14244);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-2260");
 script_bugtraq_id(10337);
 script_osvdb_id(6108);

 script_name(english:"Opera < 7.50 onUnload Address Bar Spoofing");

 script_set_attribute(attribute:"synopsis", value:
"An installed browser is vulnerable to address bar spoofing." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera - an alternative web browser.

This version of Opera is vulnerable to a security weakness 
that may permit malicious web pages to spoof address bar information.

This is reportedly possible through malicious use of the 
JavaScript 'unOnload' event handler when the browser 
is redirected to another page.

This issue could be exploited to spoof the domain of a malicious web page, 
potentially causing the user to trust the spoofed domain." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.50 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/13");
 script_cvs_date("$Date: 2012/07/13 19:28:21 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 50)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
