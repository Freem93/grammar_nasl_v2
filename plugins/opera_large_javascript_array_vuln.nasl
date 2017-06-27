#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14248);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");

 script_cve_id("CVE-2004-1810");
 script_bugtraq_id(9869);
 script_osvdb_id(59439);

 script_name(english:"Opera < 7.50 JavaScript Engine Array Handling DoS");
 script_summary(english:"Determines the version of Opera.exe");

 script_set_attribute(attribute:"synopsis", value:
"An installed browser is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Opera on the remote host is vulnerable to an issue when
handling large JavaScript arrays. 

In particular, it is possible to crash the browser when performing
various operations on Array objects with 99999999999999999999999 or
0x23000000 elements. 

The crash is due to a segmentation fault and may be indicative of an
exploitable memory corruption vulnerability, possibly resulting in
arbitrary code execution." );
 script_set_attribute(attribute:"solution", value:"Install Opera 7.50 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/10");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
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
