#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-849.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75198);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2011-2483");

  script_name(english:"openSUSE Security Update : whois (openSUSE-SU-2013:1670-1)");
  script_summary(english:"Check for the openSUSE-2013-849 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 5.0.26 [bnc#848594]

  - Added the .cf TLD server.

  - Updated the .bi TLD server.

  - Added a new ASN allocation.

  - includes changes from 5.0.25

  - Added the .ax, .bn, .iq, .pw and .rw TLD servers.

  - Updated one or more translations.

  - includes updates changes 5.0.24 :

  - Merged documentation fixes and the whois.conf(5) man
    page

  - Added a new ASN allocation.

  - Updated one or more translations.

  - includes changes from 5.0.23

  - whois.nic.or.kr switched from EUC-KR to UTF-8.

  - includes changes from 5.0.22

  - Fixed cross-compiling

  - includes changes from 5.0.21

  - Fixed parsing of 6to4 addresses

  - Added the .xn--j1amh
    (.&Ntilde;&#131;&ETH;&ordm;&Ntilde;&#128;, Ukraine) TLD
    server.

  - Updated the .bi, .se and .vn TLD servers.

  - Removed whois.pandi.or.id from the list of servers which
    support the RIPE extensions, since it does not anymore
    and queries are broken.

  - Updated some disclaimer suppression strings.

  - Respect DEB_HOST_GNU_TYPE when selecting CC for
    cross-compiling.

  - includes changes form 5.0.20

  - Updated the .by, .ng, .om, .sm, .tn, .ug and .vn TLD
    servers.

  - Added the .bw, .td, .xn--mgb9awbf
    (&Oslash;&sup1;&Ugrave;&#133;&Oslash;&sect;&Ugrave;&#134
    ;., Oman), .xn--mgberp4a5d4ar
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sup3;&Oslash;&sup
    1;&Ugrave;&#136;&Oslash;&macr;&Ugrave;&#138;&Oslash;&cop
    y;, Saudi Arabia) and .xn--mgbx4cd0ab
    (&iuml;&raquo;&cent;&iuml;&raquo;&nbsp;&iuml;&raquo;&acu
    te;&iuml;&ordm;&acute;&iuml;&raquo;&sup3;&iuml;&ordm;&#1
    41;., Malaysia) TLD servers.

  - Removed the .kp, .mc, .rw and .xn--mgba3a4f16a
    (&Oslash;&sect;&Ucirc;&#140;&Oslash;&plusmn;&Oslash;&sec
    t;&Ugrave;&#134;., Iran) TLD servers.

  - includes changes from 5.0.19

  - Added the .post TLD server.

  - Updated the .co.za SLD servers.

  - Added the .alt.za, .net.za and .web.za SLD servers.

  - whois.ua changed (?) the encoding to utf-8.

  - Fixed the parsing of 6to4 addresses like whois
    2002:xxxx::.

  - includes changes from 5.0.18

  - Updated the .ae and .xn--mgbaam7a8h
    (.&Oslash;&sect;&Ugrave;&#133;&Oslash;&sect;&Oslash;&plu
    smn;&Oslash;&sect;&Oslash;&ordf;, United Arabs Emirates)
    TLDs.

  - Updated the server charset table for .fr and .it.

  - includes changes from whois 5.0.17

  - Updated the .bi, .fo, .gr and .gt TLD servers.

  - Removed support for recursion of .org queries, it has
    been a thick registry since 2005.

  - includes changes from 5.0.16

  - Added the .xn--80ao21a
    (.&Ograve;&#154;&ETH;&#144;&ETH;&#151;, Kazakhstan) TLD
    server.

  - Updated the .ec and .ee TLD servers.

  - Removed the .xn--mgbc0a9azcg
    (.&Oslash;&sect;&Ugrave;&#132;&Ugrave;&#133;&Oslash;&ord
    m;&Oslash;&plusmn;&Oslash;&uml;, Morocco) and
    .xn--mgberp4a5d4ar
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sup3;&Oslash;&sup
    1;&Ugrave;&#136;&Oslash;&macr;&Ugrave;&#138;&Oslash;&cop
    y;, Saudi Arabia) TLD servers.

  - Added a new ASN allocation.

  - Updated one or more translations.

  - includes changes from 5.0.15

  - Added the .xn--mgba3a4f16a
    (&Oslash;&sect;&Ucirc;&#140;&Oslash;&plusmn;&Oslash;&sec
    t;&Ugrave;&#134;., Iran) TLD server.

  - Updated the .pe TLD server, this time for real.

  - Updated one or more translations.

  - includes changes from 5.0.14

  - Added the .sx TLD server.

  - Updated the .pe TLD server.

  - includes changes from 5.0.13

  - Updated the .hr TLD server.

  - Improved the package description

  - Updated the FSF address in licenses.

  - includes changes from 5.0.12

  - Recursion disabled when the query string contains
    spaces, because probably the query format will not be
    compatible with the referral server (e.g. whois to
    rwhois or ARIN to RIPE).

  - Add the '+' flag by default to queries to whois.arin.net
    if the argument looks like an IP address. Also add the
    'a' and 'n' flags. No thanks to ARIN for breaking every
    whois client.

  - Added the .cv, .lk, .mq, .sy, .so, .biz.ua, .co.ua,
    .pp.ua, .qa, .xn--3e0b707e
    (.&iacute;&#149;&#156;&ecirc;&micro;&shy;, Korea),
    .xn--45brj9c
    (.&agrave;&brvbar;&shy;&agrave;&brvbar;&frac34;&agrave;&
    brvbar;&deg;&agrave;&brvbar;&curren;, India, Bengali),
    .xn--90a3ac (.&ETH;&iexcl;&ETH;&nbsp;&ETH;&#145;,
    Serbia), .xn--clchc0ea0b2g2a9gcd
    (.&agrave;&reg;&#154;&agrave;&reg;&iquest;&agrave;&reg;&
    #153;&agrave;&macr;&#141;&agrave;&reg;&#149;&agrave;&reg
    ;&ordf;&agrave;&macr;&#141;&agrave;&reg;&ordf;&agrave;&m
    acr;&#130;&agrave;&reg;&deg;&agrave;&macr;&#141;,
    Singapore, Tamil), .xn--fpcrj9c3d
    (.&agrave;&deg;&shy;&agrave;&deg;&frac34;&agrave;&deg;&d
    eg;&agrave;&deg;&curren;&agrave;&plusmn;&#141;, India,
    Telugu), .xn--fzc2c9e2c
    (.&agrave;&para;&frac12;&agrave;&para;&#130;&agrave;&par
    a;&#154;&agrave;&middot;&#143;, Sri Lanka, Sinhala),
    .xn--gecrj9c
    (.&agrave;&ordf;&shy;&agrave;&ordf;&frac34;&agrave;&ordf
    ;&deg;&agrave;&ordf;&curren;, India, Gujarati),
    .xn--h2brj9c
    (.&agrave;&curren;&shy;&agrave;&curren;&frac34;&agrave;&
    curren;&deg;&agrave;&curren;&curren;, India, Hindi),
    .xn--lgbbat1ad8j
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&not;&Oslash;&sup2
    ;&Oslash;&sect;&Oslash;&brvbar;&Oslash;&plusmn;,
    Algeria), .xn--mgbayh7gpa
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sect;&Oslash;&plu
    smn;&Oslash;&macr;&Ugrave;&#134;, Jordan),
    .xn--mgbbh1a71e
    (.&Oslash;&uml;&Uacute;&frac34;&Oslash;&sect;&Oslash;&pl
    usmn;&Oslash;&ordf;, India, Urdu), .xn--mgbc0a9azcg
    (.&Oslash;&sect;&Ugrave;&#132;&Ugrave;&#133;&Oslash;&ord
    m;&Oslash;&plusmn;&Oslash;&uml;, Morocco), .xn--ogbpf8fl
    (.&Oslash;&sup3;&Ugrave;&#136;&Oslash;&plusmn;&Ugrave;&#
    138;&Oslash;&copy;, Syria), .xn--s9brj9c
    (.&agrave;&uml;&shy;&agrave;&uml;&frac34;&agrave;&uml;&d
    eg;&agrave;&uml;&curren;, India, Punjabi),
    .xn--xkc2al3hye2a
    (.&agrave;&reg;&#135;&agrave;&reg;&sup2;&agrave;&reg;&#1
    53;&agrave;&macr;&#141;&agrave;&reg;&#149;&agrave;&macr;
    &#136;, Sri Lanka, Tamil), .xn--wgbl6a
    (.&Ugrave;&#130;&Oslash;&middot;&Oslash;&plusmn;,
    Qatar), .xn--xkc2dl3a5ee0h
    (.&agrave;&reg;&#135;&agrave;&reg;&uml;&agrave;&macr;&#1
    41;&agrave;&reg;&curren;&agrave;&reg;&iquest;&agrave;&re
    g;&macr;&agrave;&reg;&frac34;, India, Tamil),
    .xn--yfro4i67o
    (.&aelig;&#150;&deg;&aring;&#138;&nbsp;&aring;&#157;&iex
    cl;, Singapore, Chinese) and .xxx TLD servers. (Closes:
    #642424),

  - Added the .priv.at pseudo-SLD server.

  - Updated the .co, .gf, .gp, .kr, .li, .rs, .ru, .su, .sv,
    .ua and .xn--p1ai TLD servers. (Closes: #590425,
    #634830, #627478)

  - Added a new ASN allocation.

  - Fixed a typo and -t syntax in whois(1). (Closes:
    #614973, #632588)

  - Made whois return an error in some cases, code
    contributed by David Souther.

  - Split HAVE_LINUX_CRYPT_GENSALT from HAVE_XCRYPT to
    support SuSE, which has it builtin in the libc. Added
    untested support for Solaris' crypt_gensalt(3). This and
    the following changes have been contributed by Ludwig
    Nussel of SuSE.

  - mkpasswd: stop rejecting non-ASCII characters.

  - mkpasswd: added support for the 2y algorithm, which
    fixes CVE-2011-2483.

  - mkpasswd: raised the number of rounds for 2a/2y from 4
    to 5, which is the current default.

  - mkpasswd: removed support for 2 and {SHA}, which
    actually are not supported by FreeBSD and libxcrypt.

  - packaging changes

  - removed patches accepted upstream:
    whois-5.0.11-mkpasswd-support-Owl-patched-libcrypt.diff
    whois-5.0.11-mkpasswd-crypt_gensalt-might-change-the-pre
    fix.diff
    whois-5.0.11-mkpasswd-support-8bit-characters.diff
    whois-5.0.11-mkpasswd-add-support-for-the-new-2y-blowfis
    h-tag-CVE-2011-2483.diff
    whois-5.0.11-mkpasswd-set-default-blowfish-rounds-to-5.d
    iff whois-5.0.11-mkpasswd-remove-obsolete-settings.diff

  - removed patches no longer required:
    whois-5.0.11-mkpasswd-fix-compiler-warnings.diff

  - updated patches: whois-4.7.33-nb.patch to
    whois-5.0.25-nb.patch

  - verify source signatures

  - crypt_gensalt moved to separate library libowcrypt
    (fate#314945)

  - update to 5.0.26 [bnc#848594]

  - Added the .cf TLD server.

  - Updated the .bi TLD server.

  - Added a new ASN allocation.

  - includes changes from 5.0.25

  - Added the .ax, .bn, .iq, .pw and .rw TLD servers.

  - Updated one or more translations.

  - includes updates changes 5.0.24 :

  - Merged documentation fixes and the whois.conf(5) man
    page

  - Added a new ASN allocation.

  - Updated one or more translations.

  - includes changes from 5.0.23

  - whois.nic.or.kr switched from EUC-KR to UTF-8.

  - includes changes from 5.0.22

  - Fixed cross-compiling

  - includes changes from 5.0.21

  - Fixed parsing of 6to4 addresses

  - Added the .xn--j1amh
    (.&Ntilde;&#131;&ETH;&ordm;&Ntilde;&#128;, Ukraine) TLD
    server.

  - Updated the .bi, .se and .vn TLD servers.

  - Removed whois.pandi.or.id from the list of servers which
    support the RIPE extensions, since it does not anymore
    and queries are broken.

  - Updated some disclaimer suppression strings.

  - Respect DEB_HOST_GNU_TYPE when selecting CC for
    cross-compiling.

  - includes changes form 5.0.20

  - Updated the .by, .ng, .om, .sm, .tn, .ug and .vn TLD
    servers.

  - Added the .bw, .td, .xn--mgb9awbf
    (&Oslash;&sup1;&Ugrave;&#133;&Oslash;&sect;&Ugrave;&#134
    ;., Oman), .xn--mgberp4a5d4ar
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sup3;&Oslash;&sup
    1;&Ugrave;&#136;&Oslash;&macr;&Ugrave;&#138;&Oslash;&cop
    y;, Saudi Arabia) and .xn--mgbx4cd0ab
    (&iuml;&raquo;&cent;&iuml;&raquo;&nbsp;&iuml;&raquo;&acu
    te;&iuml;&ordm;&acute;&iuml;&raquo;&sup3;&iuml;&ordm;&#1
    41;., Malaysia) TLD servers.

  - Removed the .kp, .mc, .rw and .xn--mgba3a4f16a
    (&Oslash;&sect;&Ucirc;&#140;&Oslash;&plusmn;&Oslash;&sec
    t;&Ugrave;&#134;., Iran) TLD servers.

  - includes changes from 5.0.19

  - Added the .post TLD server.

  - Updated the .co.za SLD servers.

  - Added the .alt.za, .net.za and .web.za SLD servers.

  - whois.ua changed (?) the encoding to utf-8.

  - Fixed the parsing of 6to4 addresses like whois
    2002:xxxx::.

  - includes changes from 5.0.18

  - Updated the .ae and .xn--mgbaam7a8h
    (.&Oslash;&sect;&Ugrave;&#133;&Oslash;&sect;&Oslash;&plu
    smn;&Oslash;&sect;&Oslash;&ordf;, United Arabs Emirates)
    TLDs.

  - Updated the server charset table for .fr and .it.

  - includes changes from whois 5.0.17

  - Updated the .bi, .fo, .gr and .gt TLD servers.

  - Removed support for recursion of .org queries, it has
    been a thick registry since 2005.

  - includes changes from 5.0.16

  - Added the .xn--80ao21a
    (.&Ograve;&#154;&ETH;&#144;&ETH;&#151;, Kazakhstan) TLD
    server.

  - Updated the .ec and .ee TLD servers.

  - Removed the .xn--mgbc0a9azcg
    (.&Oslash;&sect;&Ugrave;&#132;&Ugrave;&#133;&Oslash;&ord
    m;&Oslash;&plusmn;&Oslash;&uml;, Morocco) and
    .xn--mgberp4a5d4ar
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sup3;&Oslash;&sup
    1;&Ugrave;&#136;&Oslash;&macr;&Ugrave;&#138;&Oslash;&cop
    y;, Saudi Arabia) TLD servers.

  - Added a new ASN allocation.

  - Updated one or more translations.

  - includes changes from 5.0.15

  - Added the .xn--mgba3a4f16a
    (&Oslash;&sect;&Ucirc;&#140;&Oslash;&plusmn;&Oslash;&sec
    t;&Ugrave;&#134;., Iran) TLD server.

  - Updated the .pe TLD server, this time for real.

  - Updated one or more translations.

  - includes changes from 5.0.14

  - Added the .sx TLD server.

  - Updated the .pe TLD server.

  - includes changes from 5.0.13

  - Updated the .hr TLD server.

  - Improved the package description

  - Updated the FSF address in licenses.

  - includes changes from 5.0.12

  - Recursion disabled when the query string contains
    spaces, because probably the query format will not be
    compatible with the referral server (e.g. whois to
    rwhois or ARIN to RIPE).

  - Add the '+' flag by default to queries to whois.arin.net
    if the argument looks like an IP address. Also add the
    'a' and 'n' flags. No thanks to ARIN for breaking every
    whois client.

  - Added the .cv, .lk, .mq, .sy, .so, .biz.ua, .co.ua,
    .pp.ua, .qa, .xn--3e0b707e
    (.&iacute;&#149;&#156;&ecirc;&micro;&shy;, Korea),
    .xn--45brj9c
    (.&agrave;&brvbar;&shy;&agrave;&brvbar;&frac34;&agrave;&
    brvbar;&deg;&agrave;&brvbar;&curren;, India, Bengali),
    .xn--90a3ac (.&ETH;&iexcl;&ETH;&nbsp;&ETH;&#145;,
    Serbia), .xn--clchc0ea0b2g2a9gcd
    (.&agrave;&reg;&#154;&agrave;&reg;&iquest;&agrave;&reg;&
    #153;&agrave;&macr;&#141;&agrave;&reg;&#149;&agrave;&reg
    ;&ordf;&agrave;&macr;&#141;&agrave;&reg;&ordf;&agrave;&m
    acr;&#130;&agrave;&reg;&deg;&agrave;&macr;&#141;,
    Singapore, Tamil), .xn--fpcrj9c3d
    (.&agrave;&deg;&shy;&agrave;&deg;&frac34;&agrave;&deg;&d
    eg;&agrave;&deg;&curren;&agrave;&plusmn;&#141;, India,
    Telugu), .xn--fzc2c9e2c
    (.&agrave;&para;&frac12;&agrave;&para;&#130;&agrave;&par
    a;&#154;&agrave;&middot;&#143;, Sri Lanka, Sinhala),
    .xn--gecrj9c
    (.&agrave;&ordf;&shy;&agrave;&ordf;&frac34;&agrave;&ordf
    ;&deg;&agrave;&ordf;&curren;, India, Gujarati),
    .xn--h2brj9c
    (.&agrave;&curren;&shy;&agrave;&curren;&frac34;&agrave;&
    curren;&deg;&agrave;&curren;&curren;, India, Hindi),
    .xn--lgbbat1ad8j
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&not;&Oslash;&sup2
    ;&Oslash;&sect;&Oslash;&brvbar;&Oslash;&plusmn;,
    Algeria), .xn--mgbayh7gpa
    (.&Oslash;&sect;&Ugrave;&#132;&Oslash;&sect;&Oslash;&plu
    smn;&Oslash;&macr;&Ugrave;&#134;, Jordan),
    .xn--mgbbh1a71e
    (.&Oslash;&uml;&Uacute;&frac34;&Oslash;&sect;&Oslash;&pl
    usmn;&Oslash;&ordf;, India, Urdu), .xn--mgbc0a9azcg
    (.&Oslash;&sect;&Ugrave;&#132;&Ugrave;&#133;&Oslash;&ord
    m;&Oslash;&plusmn;&Oslash;&uml;, Morocco), .xn--ogbpf8fl
    (.&Oslash;&sup3;&Ugrave;&#136;&Oslash;&plusmn;&Ugrave;&#
    138;&Oslash;&copy;, Syria), .xn--s9brj9c
    (.&agrave;&uml;&shy;&agrave;&uml;&frac34;&agrave;&uml;&d
    eg;&agrave;&uml;&curren;, India, Punjabi),
    .xn--xkc2al3hye2a
    (.&agrave;&reg;&#135;&agrave;&reg;&sup2;&agrave;&reg;&#1
    53;&agrave;&macr;&#141;&agrave;&reg;&#149;&agrave;&macr;
    &#136;, Sri Lanka, Tamil), .xn--wgbl6a
    (.&Ugrave;&#130;&Oslash;&middot;&Oslash;&plusmn;,
    Qatar), .xn--xkc2dl3a5ee0h
    (.&agrave;&reg;&#135;&agrave;&reg;&uml;&agrave;&macr;&#1
    41;&agrave;&reg;&curren;&agrave;&reg;&iquest;&agrave;&re
    g;&macr;&agrave;&reg;&frac34;, India, Tamil),
    .xn--yfro4i67o
    (.&aelig;&#150;&deg;&aring;&#138;&nbsp;&aring;&#157;&iex
    cl;, Singapore, Chinese) and .xxx TLD servers. (Closes:
    #642424),

  - Added the .priv.at pseudo-SLD server.

  - Updated the .co, .gf, .gp, .kr, .li, .rs, .ru, .su, .sv,
    .ua and .xn--p1ai TLD servers. (Closes: #590425,
    #634830, #627478)

  - Added a new ASN allocation.

  - Fixed a typo and -t syntax in whois(1). (Closes:
    #614973, #632588)

  - Made whois return an error in some cases, code
    contributed by David Souther.

  - Split HAVE_LINUX_CRYPT_GENSALT from HAVE_XCRYPT to
    support SuSE, which has it builtin in the libc. Added
    untested support for Solaris' crypt_gensalt(3). This and
    the following changes have been contributed by Ludwig
    Nussel of SuSE.

  - mkpasswd: stop rejecting non-ASCII characters.

  - mkpasswd: added support for the 2y algorithm, which
    fixes CVE-2011-2483.

  - mkpasswd: raised the number of rounds for 2a/2y from 4
    to 5, which is the current default.

  - mkpasswd: removed support for 2 and {SHA}, which
    actually are not supported by FreeBSD and libxcrypt.

  - packaging changes

  - removed patches accepted upstream:
    whois-5.0.11-mkpasswd-support-Owl-patched-libcrypt.diff
    whois-5.0.11-mkpasswd-crypt_gensalt-might-change-the-pre
    fix.diff
    whois-5.0.11-mkpasswd-support-8bit-characters.diff
    whois-5.0.11-mkpasswd-add-support-for-the-new-2y-blowfis
    h-tag-CVE-2011-2483.diff
    whois-5.0.11-mkpasswd-set-default-blowfish-rounds-to-5.d
    iff whois-5.0.11-mkpasswd-remove-obsolete-settings.diff

  - removed patches no longer required:
    whois-5.0.11-mkpasswd-fix-compiler-warnings.diff

  - updated patches: whois-4.7.33-nb.patch to
    whois-5.0.25-nb.patch

  - verify source signatures

  - crypt_gensalt moved to separate library libowcrypt
    (fate#314945)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848594"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected whois packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:whois");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:whois-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:whois-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"whois-5.0.26-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"whois-debuginfo-5.0.26-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"whois-debugsource-5.0.26-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"whois-5.0.26-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"whois-debuginfo-5.0.26-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"whois-debugsource-5.0.26-12.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "whois / whois-debuginfo / whois-debugsource");
}
