#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22336);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-4381", "CVE-2006-4382", "CVE-2006-4384", "CVE-2006-4385", "CVE-2006-4386", 
                "CVE-2006-4388", "CVE-2006-4389", "CVE-2007-0754");
  script_bugtraq_id(19976, 23923);
  script_osvdb_id(28768, 28769, 28770, 28771, 28772, 28773, 28774, 35574);

  script_name(english:"QuickTime < 7.1.3 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of QuickTime prior to
7.1.3. 

The remote version of QuickTime is vulnerable to various integer and
buffer overflows involving specially crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304357" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 7.1.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/12");
 script_cvs_date("$Date: 2011/09/23 20:23:06 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.(0\.|1\.[0-2]([^0-9]|$)))"
) security_hole(get_kb_item("SMB/transport"));
