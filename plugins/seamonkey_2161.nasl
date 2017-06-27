#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65187);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/10/01 11:06:37 $");

  script_cve_id("CVE-2013-0787");
  script_bugtraq_id(58391);
  script_osvdb_id(90928);

  script_name(english:"SeaMonkey < 2.16.1 nsHTMLEditor Use-After-Free");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by a use-after-free vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of SeaMonkey is earlier than 2.16.1 and thus,
is potentially affected by a use-after-free vulnerability. 

An error exists in the HTML editor (nsHTMLEditor) related to content
script and the calling of the function 'document.execCommand' while
internal editor operations are running.  The previously freed memory can
be dereferenced and could lead to arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526050/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-090/");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-29.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.16.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}
 
include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.16.1', severity:SECURITY_HOLE);
