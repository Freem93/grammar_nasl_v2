#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91784);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/23 13:29:51 $");

  script_cve_id(
    "CVE-2016-2365",
    "CVE-2016-2366",
    "CVE-2016-2367",
    "CVE-2016-2368",
    "CVE-2016-2369",
    "CVE-2016-2370",
    "CVE-2016-2371",
    "CVE-2016-2372",
    "CVE-2016-2373",
    "CVE-2016-2374",
    "CVE-2016-2375",
    "CVE-2016-2376",
    "CVE-2016-2377",
    "CVE-2016-2378",
    "CVE-2016-2379",
    "CVE-2016-2380",
    "CVE-2016-4323"
  );
  script_osvdb_id(
    140394,
    140395,
    140396,
    140397,
    140398,
    140399,
    140400,
    140401,
    140402,
    140403,
    140404,
    140405,
    140406,
    140407,
    140408,
    140409,
    140410,
    140411
  );

  script_name(english:"Pidgin < 2.11.0 Multiple Vulnerabilities");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging client installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Pidgin installed on the remote Windows host is prior to 
2.11.0. It is, therefore, affected by multiple vulnerabilities :

  - A NULL pointer dereference flaw exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT data, to cause a denial of service.
    (CVE-2016-2365)

  - Multiple out-of-bounds read errors exist when handling
    the MXIT protocol. A remote attacker can exploit these,
    via crafted MXIT data, to cause a denial of service.
    (CVE-2016-2366, CVE-2016-2370)

  - An out-of-bounds read error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    an invalid size for an avatar, to disclose memory
    contents or cause a denial of service. (CVE-2016-2367)

  - Multiple memory corruption issues exist when handling
    the MXIT protocol. A remote attacker can exploit these,
    via crafted MXIT data, to disclose memory contents or
    execute arbitrary code. (CVE-2016-2368)

  - A NULL pointer dereference flaw exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT packet starting with a NULL byte, to cause
    a denial of service. (CVE-2016-2369)

  - An out-of-bounds write error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT data, to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2371)

  - An out-of-bounds read error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    an invalid size for a file transfer, to disclose memory
    contents or cause a denial of service. (CVE-2016-2372)

  - An out-of-bounds read error exists when handling the
    MXIT protocol. A remote attacker can exploit this, by
    sending an invalid mood, to cause a denial of service.
    (CVE-2016-2373)

  - An out-of-bounds write error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT MultiMX messages, to disclose memory
    contents or execute arbitrary code. (CVE-2016-2374)

  - An out-of-bounds read error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT contact information, to disclose memory
    contents. (CVE-2016-2375)

  - A buffer overflow condition exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    a crafted packet having an invalid size, to execute
    arbitrary code. (CVE-2016-2376)

  - An out-of-bounds write error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    a negative content-length response to an HTTP request,
    to cause a denial of service. (CVE-2016-2377)

  - A buffer overflow condition exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted data using negative length values, to cause a
    denial of service. (CVE-2016-2378)

  - A flaw exists in MXIT due to using weak cryptography
    when encrypting a user password. A man-in-the-middle
    attacker able to access login messages can exploit this
    to impersonate the user. (CVE-2016-2379)

  - An out-of-bounds read error exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    a crafted local message, to disclose memory contents.
    (CVE-2016-2380)

  - A directory traversal flaw exists when handling the
    MXIT protocol. A remote attacker can exploit this, via
    crafted MXIT data using an invalid file name for a
    splash image, to overwrite files. (CVE-2016-4323)

  - An unspecified vulnerability exists due to X.509
    certificates not being properly imported when using
    GnuTLS. No other details are available.
    (VulnDB 140411)");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=91");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=92");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=93");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=94");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=95");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=96");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=97");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=98");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=99");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=100");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=101");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=102");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=103");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=104");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=105");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=106");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=107");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=108");  
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pidgin version 2.11.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.11.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port)) port = 445;

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version +
    '\n  Fixed version      : ' + fixed_version + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
