#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44659);
  script_version("$Revision: 1.17 $");

  script_cve_id(
    "CVE-2009-1571",
    "CVE-2009-3988",
    "CVE-2010-0159",
    "CVE-2010-0160",
    "CVE-2010-0162",
    "CVE-2010-0165",
    "CVE-2010-0167",
    "CVE-2010-0169",
    "CVE-2010-0171",
    "CVE-2010-0179"
  );
  script_bugtraq_id(
    38285,
    38286,
    38287,
    38288,
    38289,
    38922,
    38939,
    38944,
    38946,
    39124
  );
  script_osvdb_id(
    62418,
    62419,
    62420,
    62421,
    62422,
    62423,
    62424,
    62425,
    62426,
    62427,
    62428,
    63265,
    63267,
    63268,
    63270,
    63272,
    63637
  );
  script_xref(name:"Secunia", value:"37242");

  script_name(english:"Firefox 3.5 < 3.5.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Firefox is 3.5.x earlier than 3.5.8.  Such
versions are potentially affected by the following security issues :

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-01)

  - The implementation of 'Web Workers' contained an error 
    in its handling of array data types when processing 
    posted messages. (MFSA 2010-02)

  - The HTML parser incorrectly frees used memory when
    insufficient space is available to process remaining
    input. (MFSA 2010-03)

  - A cross-site scripting issue exists due to
    'window.dialogArguments' being readable cross-domain.
    (MFSA 2010-04)

  - A cross-site scripting issue exists when using SVG 
    documents and binary Content-Type. (MFSA 2010-05)
    
  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-11)

  - A cross-site scripting issue when using
    'addEventListener' and 'setTimeout' on a wrapped object.
    (MFSA 2010-12)

  - It is possible to corrupt a user's XUL cache. 
    (MFSA 2010-14)

  - The XMLHttpRequestSpy module in the Firebug add-on 
    exposes an underlying chrome privilege escalation
    vulnerability. (MFSA 2010-21)");

  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-01.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-02.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-03.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-04.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-05.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-12.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-14.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-21.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Firefox 3.5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 94, 264, 399);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/18");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.8', min:'3.5', severity:SECURITY_HOLE);