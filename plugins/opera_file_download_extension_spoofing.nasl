#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14247);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-2083");
 script_bugtraq_id(9640);
 script_osvdb_id(3917);

 script_name(english:"Opera < 7.50 File Download Extension Spoofing");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host contains a flaw that
may allow a malicious user to trick a user into running arbitrary
code. 

The issue is triggered when an malicious website provides a file for
download, but crafts the filename in such a way that the file is
executed, rather than saved. 

It is possible that the flaw may allow arbitrary code execution
resulting in a loss of confidentiality, integrity, and/or
availability." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.50 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/11");
 script_cvs_date("$Date: 2014/04/25 21:05:49 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
