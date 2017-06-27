#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40479);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2009-2654", 
    "CVE-2009-2470", 
    "CVE-2009-2662", 
    "CVE-2009-2663", 
    "CVE-2009-2664",
    "CVE-2009-2665", 
    "CVE-2009-3071", 
    "CVE-2009-3075"
  );
  script_bugtraq_id(35803, 35925, 35927, 35928, 36018, 36343);
  script_osvdb_id(
    56716,
    56717,
    56718,
    56719,
    56720,
    56721,
    56722,
    57973,
    57976
  );
  script_xref(name:"Secunia", value:"36001");

  script_name(english:"Firefox 3.5.x < 3.5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version number");

  script_set_attribute( attribute:"synopsis",   value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",  value:
"The installed version of Firefox 3.5 is earlier than 3.5.2.  Such 
versions are potentially affected by the following security issues :

  - A SOCKS5 proxy that replies with a hostname containing
    more than 15 characters can corrupt the subsequent
    data stream.  This can lead to a denial of service,
    though there is reportedly no memory corruption.
    (MFSA 2009-38)

  - The location bar and SSL indicators can be spoofed
    by calling window.open() on an invalid URL. A remote
    attacker could use this to perform a phishing attack.
    (MFSA 2009-44)

  - Unspecified JavaScript-related vulnerabilities can lead
    to memory corruption, and possibly arbitrary execution
    of code. (MFSA 2009-45, MFSA 2009-47)

  - If an add-on has a 'Link:' HTTP header when it is installed,
    the window's global object receives an incorrect security
    wrapper, which could lead to arbitrary JavaScript being
    executed with chrome privileges. (MFSA 2009-46)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119, 399);
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/21");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.2', min:'3.5', severity:SECURITY_HOLE);