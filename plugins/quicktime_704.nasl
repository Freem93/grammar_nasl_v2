#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20395);
  script_version("$Revision: 1.26 $");

  script_cve_id("CVE-2005-2340", "CVE-2005-3707", "CVE-2005-3708", "CVE-2005-3709", "CVE-2005-3710",
                "CVE-2005-3711", "CVE-2005-3713", "CVE-2005-4092");
  script_bugtraq_id(16852, 16864, 16867, 16869, 16872, 16873, 16875);
  script_osvdb_id(21840, 22333, 22334, 22335, 22336, 22337, 22338);

  script_name(english:"QuickTime < 7.0.4 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks for QuickTime < 7.0.4 on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple code execution
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of QuickTime prior to
7.0.4. 

The remote version of QuickTime is vulnerable to various buffer
overflows involving specially crafted image and media files.  An
attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
have him open it using QuickTime player." );
 # https://dl.packetstormsecurity.net/0601-advisories/cirt-41-advisory.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d477727" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/397" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/401" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/403" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/405" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/406" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jan/msg00001.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303101" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 7.0.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/11");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/01/11");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.[0-3]$)") security_hole(get_kb_item("SMB/transport"));
