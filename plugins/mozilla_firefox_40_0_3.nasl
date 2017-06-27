#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85689);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/26 18:46:52 $");

  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_osvdb_id(126767, 126768);

  script_name(english:"Firefox < 40.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 40.0.3. It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists when handling restyling
    operations during the resizing of canvas elements due to
    the canvas references being recreated, thus destroying
    the original references. A remote, unauthenticated
    attacker can exploit this to deference already freed
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2015-4497)

  - A security feature bypass vulnerability exists due to a
    flaw that allows the manipulation of the 'data:' URL on
    a loaded web page without install permission prompts
    being displayed to the user. A remote, unauthenticated
    attacker can exploit this to install add-ons from a
    malicious source. (CVE-2015-4498)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-94/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-95/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 40.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'40.0.3', severity:SECURITY_HOLE, xss:FALSE);
