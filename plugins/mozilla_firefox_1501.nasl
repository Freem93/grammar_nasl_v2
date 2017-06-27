#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20842);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294", "CVE-2006-0295",
                "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298", "CVE-2006-0299");
  script_bugtraq_id(15773, 16476, 16741);
  script_osvdb_id(
    21533,
    22890,
    22891,
    22892,
    22893,
    22894,
    22895,
    22896,
    22897,
    22898,
    22899
  );

  script_name(english:"Firefox < 1.5.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for Firefox < 1.5.0.1");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues, some
of which can be exploited to execute arbitrary code on the affected host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425590/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/04");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/07");
 script_cvs_date("$Date: 2013/11/27 17:20:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.5.0.1', severity:SECURITY_HOLE);