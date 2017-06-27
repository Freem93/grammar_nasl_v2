#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83464);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2011-3079",
    "CVE-2015-2708",
    "CVE-2015-2710",
    "CVE-2015-2713",
    "CVE-2015-2716"
  );
  script_bugtraq_id(
    53309,
    74611,
    74615
  );
  script_osvdb_id(
    122020,
    122021,
    122022,
    122023,
    122033,
    122036,
    122039,
    81645
  );

  script_name(english:"Mozilla Thunderbird < 31.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is
prior to 31.7. It is, therefore, affected by the following
vulnerabilities :

  - A privilege escalation vulnerability exists in the
    Inter-process Communications (IPC) implementation due
    to a failure to validate the identity of a listener
    process. (CVE-2011-3079)

  - Multiple memory corruption issues exist within the
    browser engine. A remote attacker can exploit these to
    corrupt memory and execute arbitrary code.
    (CVE-2015-2708)

  - A buffer overflow condition exists in SVGTextFrame.cpp
    when rendering SVG graphics that are combined with
    certain CSS properties due to improper validation of
    user-supplied input. A remote attacker can exploit this
    to cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2015-2710)

  - A use-after-free error exists due to improper processing
    of text when vertical text is enabled. A remote attacker
    can exploit this to dereference already freed memory.
    (CVE-2015-2713)

  - A buffer overflow condition exists in the
    XML_GetBuffer() function in xmlparse.c due to improper
    validation of user-supplied input when handling
    compressed XML content. An attacker can exploit this to
    cause a buffer overflow, resulting in the execution of
    arbitrary code. (CVE-2015-2716)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-57/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 31.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'31.7', min:'31.0', severity:SECURITY_HOLE);
