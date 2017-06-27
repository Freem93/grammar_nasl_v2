#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50087);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3178",
                "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3181", "CVE-2010-3183");
  script_bugtraq_id(42817, 44243, 44245, 44247, 44248, 44249, 44250, 44252);
  script_osvdb_id(
    68079,
    68844,
    68846,
    68847,
    68849,
    68850,
    68851,
    68852,
    68854
  );
  script_xref(name:"Secunia", value:"41890");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.5.  Such
versions are potentially affected by the following security issues :

  - Multiple memory safety bugs could lead to memory
    corruption, potentially resulting in arbitrary
    code execution. (MFSA 2010-64)

  - By passing an excessively long string to
    'document.write', it may be possible to trigger a buffer
    overflow condition resulting in arbitrary code execution
    on the remote system. (MFSA 2010-65)

  - A use-after-free error in nsBarProp could allow
    arbitrary code execution on the remote system.
    (MFSA 2010-66)

  - A dangling pointer vulnerability in LookupGetterOrSetter
    could allow arbitrary code execution. (MFSA 2010-67)

  - It is possible to steal information from a site in a
    different domain using modal calls. (MFSA 2010-69)

  - It is possible to establish a valid SSL connection
    to a remote host, provided the SSL certificate was
    created with a common name containing a wild card
    followed by partial IP address of the remote host.
    (MFSA 2010-70)

  - A function used to load external libraries on Windows
    platform could allow loading of unsafe DLLs thus
    allowing binary planting attacks. (MFSA 2010-71)

  - The SSL implementation allows servers to use
    Diffie-Hellman Ephemeral mode (DHE) with a very
    short key length. Such key lengths could be easily
    breakable with modern hardware. (MFSA 2010-72)");

  script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-10-0001.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-219/");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-64.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-65.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-66.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-67.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-69.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-70.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-71.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-72.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird31.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/14"); # MFSA 2010-70 
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.5', min:'3.1.0', severity:SECURITY_HOLE);