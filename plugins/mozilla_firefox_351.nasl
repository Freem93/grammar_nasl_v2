#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39853);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2009-2467", "CVE-2009-2477");
  script_bugtraq_id(35660,35767);
  script_osvdb_id(55846, 56227);

  script_name(english:"Firefox 3.5.x < 3.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is 
affected by multiple flaws." );

  script_set_attribute(attribute:"description", value:
"Firefox 3.5 is installed on the remote host.  This version is
potentially affected by multiple flaws :

  - It may be possible to crash the browser or potentially
    execute arbitrary code by using a flash object that
    presents a slow script dialog. (MFSA 2009-35)

  - In certain cases after a return from a native function,
    such as escape(), the Just-in-Time (JIT) compiler could
    get into a corrupt state. An attacker who is able to
    trick a user of the affected software into visiting a
    malicious link may be able to leverage this issue to
    run arbitrary code subject to the user's privileges.
    (MFSA 2009-41)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-35.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-41.html" );
  script_set_attribute(attribute:"solution", value: "Upgrade to Firefox 3.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 3.5 escape() Return Value Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date",  value:"2009/07/13");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date",  value:"2009/07/17");

 script_cvs_date("$Date: 2016/12/21 14:22:36 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.1', min:'3.5', severity:SECURITY_HOLE);