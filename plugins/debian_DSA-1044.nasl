#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1044. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22586);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_bugtraq_id(15773, 16476, 17516);
  script_osvdb_id(21533, 22890, 22892, 22894, 24658, 24659, 24660, 24661, 24662, 24663, 24664, 24665, 24666, 24667, 24668, 24669, 24670, 24671, 24677, 24678, 24679, 24680, 24947, 79168, 79169);
  script_xref(name:"CERT", value:"179014");
  script_xref(name:"CERT", value:"252324");
  script_xref(name:"CERT", value:"329500");
  script_xref(name:"CERT", value:"488774");
  script_xref(name:"CERT", value:"492382");
  script_xref(name:"CERT", value:"592425");
  script_xref(name:"CERT", value:"736934");
  script_xref(name:"CERT", value:"813230");
  script_xref(name:"CERT", value:"842094");
  script_xref(name:"CERT", value:"932734");
  script_xref(name:"CERT", value:"935556");
  script_xref(name:"DSA", value:"1044");

  script_name(english:"Debian DSA-1044-1 : mozilla-firefox - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in Mozilla
Firefox. The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities :

  - CVE-2005-4134
    Web pages with extremely long titles cause subsequent
    launches of the browser to appear to 'hang' for up to a
    few minutes, or even crash if the computer has
    insufficient memory. [MFSA-2006-03]

  - CVE-2006-0292
    The JavaScript interpreter does not properly dereference
    objects, which allows remote attackers to cause a denial
    of service or execute arbitrary code. [MFSA-2006-01]

  - CVE-2006-0293
    The function allocation code allows attackers to cause a
    denial of service and possibly execute arbitrary code.
    [MFSA-2006-01]

  - CVE-2006-0296
    XULDocument.persist() did not validate the attribute
    name, allowing an attacker to inject arbitrary XML and
    JavaScript code into localstore.rdf that would be read
    and acted upon during startup. [MFSA-2006-05]

  - CVE-2006-0748
    An anonymous researcher for TippingPoint and the Zero
    Day Initiative reported that an invalid and nonsensical
    ordering of table-related tags can be exploited to
    execute arbitrary code. [MFSA-2006-27]

  - CVE-2006-0749
    A particular sequence of HTML tags can cause memory
    corruption that can be exploited to execute arbitrary
    code. [MFSA-2006-18]

  - CVE-2006-1727
    Georgi Guninski reported two variants of using scripts
    in an XBL control to gain chrome privileges when the
    page is viewed under 'Print Preview'. [MFSA-2006-25]

  - CVE-2006-1728
    'shutdown' discovered that the
    crypto.generateCRMFRequest method can be used to run
    arbitrary code with the privilege of the user running
    the browser, which could enable an attacker to install
    malware. [MFSA-2006-24]

  - CVE-2006-1729
    Claus Jorgensen reported that a text input box can be
    pre-filled with a filename and then turned into a
    file-upload control, allowing a malicious website to
    steal any local file whose name they can guess.
    [MFSA-2006-23]

  - CVE-2006-1730
    An anonymous researcher for TippingPoint and the Zero
    Day Initiative discovered an integer overflow triggered
    by the CSS letter-spacing property, which could be
    exploited to execute arbitrary code. [MFSA-2006-22]

  - CVE-2006-1731
    'moz_bug_r_a4' discovered that some internal functions
    return prototypes instead of objects, which allows
    remote attackers to conduct cross-site scripting
    attacks. [MFSA-2006-19]

  - CVE-2006-1732
    'shutdown' discovered that it is possible to bypass
    same-origin protections, allowing a malicious site to
    inject script into content from another site, which
    could allow the malicious page to steal information such
    as cookies or passwords from the other site, or perform
    transactions on the user's behalf if the user were
    already logged in. [MFSA-2006-17]

  - CVE-2006-1733
    'moz_bug_r_a4' discovered that the compilation scope of
    privileged built-in XBL bindings is not fully protected
    from web content and can still be executed which could
    be used to execute arbitrary JavaScript, which could
    allow an attacker to install malware such as viruses and
    password sniffers. [MFSA-2006-16]

  - CVE-2006-1734
    'shutdown' discovered that it is possible to access an
    internal function object which could then be used to run
    arbitrary JavaScript code with full permissions of the
    user running the browser, which could be used to install
    spyware or viruses. [MFSA-2006-15]

  - CVE-2006-1735
    It is possible to create JavaScript functions that would
    get compiled with the wrong privileges, allowing an
    attacker to run code of their choice with full
    permissions of the user running the browser, which could
    be used to install spyware or viruses. [MFSA-2006-14]

  - CVE-2006-1736
    It is possible to trick users into downloading and
    saving an executable file via an image that is overlaid
    by a transparent image link that points to the
    executable. [MFSA-2006-13]

  - CVE-2006-1737
    An integer overflow allows remote attackers to cause a
    denial of service and possibly execute arbitrary
    bytecode via JavaScript with a large regular expression.
    [MFSA-2006-11]

  - CVE-2006-1738
    An unspecified vulnerability allows remote attackers to
    cause a denial of service. [MFSA-2006-11]

  - CVE-2006-1739
    Certain Cascading Style Sheets (CSS) can cause an
    out-of-bounds array write and buffer overflow that could
    lead to a denial of service and the possible execution
    of arbitrary code. [MFSA-2006-11]

  - CVE-2006-1740
    It is possible for remote attackers to spoof secure site
    indicators such as the locked icon by opening the
    trusted site in a popup window, then changing the
    location to a malicious site. [MFSA-2006-12]

  - CVE-2006-1741
    'shutdown' discovered that it is possible to inject
    arbitrary JavaScript code into a page on another site
    using a modal alert to suspend an event handler while a
    new page is being loaded. This could be used to steal
    confidential information. [MFSA-2006-09]

  - CVE-2006-1742
    Igor Bukanov discovered that the JavaScript engine does
    not properly handle temporary variables, which might
    allow remote attackers to trigger operations on freed
    memory and cause memory corruption. [MFSA-2006-10]

  - CVE-2006-1790
    A regression fix that could lead to memory corruption
    allows remote attackers to cause a denial of service and
    possibly execute arbitrary code. [MFSA-2006-11]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=363935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=362656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1044"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla Firefox packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.1", prefix:"mozilla-firefox", reference:"1.0.4-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-dom-inspector", reference:"1.0.4-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-gnome-support", reference:"1.0.4-2sarge6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
