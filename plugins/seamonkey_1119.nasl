#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45111);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2009-0689",
    "CVE-2009-2463",
    "CVE-2009-2072",
    "CVE-2009-3075",
    "CVE-2009-3077",
    "CVE-2009-3385",
    "CVE-2009-3983",
    "CVE-2010-0161", 
    "CVE-2010-0163"
  );
  script_bugtraq_id(37366, 38830, 38831);
  script_osvdb_id(
    55603,
    56230,
    56486,
    57972,
    57976,
    57978,
    61091,
    61101,
    63261,
    63262,
    63263
  );
  script_xref(name:"Secunia", value:"39001");

  script_name(english:"SeaMonkey < 1.1.19 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"A web browser on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 1.1.19.  Such
versions are potentially affected by the following security issues :
  
  - The columns of a XUL tree element can be manipulated in
    a particular way that would leave a pointer owned by
    the column pointing to freed memory. (MFSA 2009-49)

  - A heap-based buffer overflow exists in Mozilla's string
    to floating point number conversion routines. 
    (MFSA 2009-59)

  - It is possible to obfuscate the name of files to be
    downloaded by using a right-to-left override character
    (RTL). (MFSA 2009-62)

  - Mozilla's NTLM implementation is vulnerable to 
    reflection attacks in which NTLM credentials from one
    application could be forwarded to another arbitrary 
    application. (MFSA 2009-68)

  - Scriptable plugin content, such as Flash objects, can be
    loaded and executed by embedding the content in an 
    iframe inside the message. (MFSA 2010-06)

  - Multiple memory corruption vulnerabilities exist that
    may result in the execution of arbitrary code. 
    (MFSA 2010-07)");

  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-06.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-07.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-68.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2009/mfsa2009-49.html");
  script_set_attribute(attribute:"solution",value:
"Upgrade to SeaMonkey 2.0.3 / 1.1.19 or later. 

Note that 1.1.19 is a legacy release and is affected by known
vulnerabilities.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119, 189, 287);

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/09/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/19");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");
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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.19', severity:SECURITY_HOLE);