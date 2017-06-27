#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47125);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/09/24 14:12:00 $");

  script_cve_id("CVE-2010-1121", "CVE-2010-1196", "CVE-2010-1199");
  script_bugtraq_id(38952, 41082, 41087);
  script_osvdb_id(63457, 65735, 65744);
  script_xref(name:"Secunia", value:"40323");

  script_name(english:"Mozilla Thunderbird < 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 3.0.5.  Such
versions are potentially affected by the following security issues :

  - A memory corruption vulnerability can lead to arbitrary
    code execution if garbage collection is carefully timed
    after DOM nodes are moved between documents.
    (MFSA 2010-25)

  - Multiple crashes can result in arbitrary code
    execution. (MFSA 2010-26)

  - An error in 'nsGenericDOMDataNode' allows a buffer
    overflow in certain DOM nodes leading to arbitrary code
    execution. (MFSA 2010-29)

  - An error in a XSLT node sorting function contains an
    integer overflow leading to application crashes and
    possible arbitrary code execution. (MFSA 2010-30)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-29.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-30.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.0.5', severity:SECURITY_HOLE);