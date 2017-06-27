#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50386);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id("CVE-2010-3765");
  script_bugtraq_id(44425);
  script_osvdb_id(68905, 68921);
  script_xref(name:"EDB-ID", value:"15342");
  script_xref(name:"Secunia", value:"41957");

  script_name(english:"SeaMonkey < 2.0.10 Buffer Overflow");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.10.  Such
versions are potentially affected by a heap-based buffer overflow
vulnerability. 

The combination of DOM insertions and the handling of the JavaScript
function 'document.write()' exposes an error that can lead to a
heap-based buffer overflow. 

Note that there have been reports that this issue is being actively
exploited in the wild.");

  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=607222");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-73.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Interleaved document.write/appendChild Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.10', severity:SECURITY_HOLE);