#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-132.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75256);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6486", "CVE-2013-6487", "CVE-2014-0020");
  script_bugtraq_id(65188, 65189, 65243, 65492);

  script_name(english:"openSUSE Security Update : pidgin / pidgin-branding-openSUSE (openSUSE-SU-2014:0239-1)");
  script_summary(english:"Check for the openSUSE-2014-132 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 2.10.8 (bnc#861019) :

  + General: Python build scripts and example plugins are
    now compatible with Python 3 (pidgin.im#15624).

  + libpurple :

  - Fix potential crash if libpurple gets an error
    attempting to read a reply from a STUN server
    (CVE-2013-6484).

  - Fix potential crash parsing a malformed HTTP response
    (CVE-2013-6479).

  - Fix buffer overflow when parsing a malformed HTTP
    response with chunked Transfer-Encoding (CVE-2013-6485).

  - Better handling of HTTP proxy responses with negative
    Content-Lengths.

  - Fix handling of SSL certificates without subjects when
    using libnss.

  - Fix handling of SSL certificates with timestamps in the
    distant future when using libnss (pidgin.im#15586).

  - Impose maximum download size for all HTTP fetches.

  + Pidgin :

  - Fix crash displaying tooltip of long URLs
    (CVE-2013-6478).

  - Better handling of URLs longer than 1000 letters.

  - Fix handling of multibyte UTF-8 characters in smiley
    themes (pidgin.im#15756).

  + AIM: Fix untrusted certificate error.

  + AIM and ICQ: Fix a possible crash when receiving a
    malformed message in a Direct IM session.

  + Gadu-Gadu :

  - Fix buffer overflow with remote code execution
    potential. Only triggerable by a Gadu-Gadu server or a
    man-in-the-middle (CVE-2013-6487).

  - Disabled buddy list import/export from/to server.

  - Disabled new account registration and password change
    options.

  + IRC :

  - Fix bug where a malicious server or man-in-the-middle
    could trigger a crash by not sending enough arguments
    with various messages (CVE-2014-0020).

  - Fix bug where initial IRC status would not be set
    correctly.

  - Fix bug where IRC wasn't available when libpurple was
    compiled with Cyrus SASL support (pidgin.im#15517).

  + MSN :

  - Fix NULL pointer dereference parsing headers in MSN
    (CVE-2013-6482).

  - Fix NULL pointer dereference parsing OIM data in MSN
    (CVE-2013-6482).

  - Fix NULL pointer dereference parsing SOAP data in MSN
    (CVE-2013-6482).

  - Fix possible crash when sending very long messages. Not
    remotely-triggerable.

  + MXit :

  - Fix buffer overflow with remote code execution potential
    (CVE-2013-6487).

  - Fix sporadic crashes that can happen after user is
    disconnected.

  - Fix crash when attempting to add a contact via search
    results.

  - Show error message if file transfer fails.

  - Fix compiling with InstantBird.

  - Fix display of some custom emoticons.

  + SILC: Correctly set whiteboard dimensions in whiteboard
    sessions.

  + SIMPLE: Fix buffer overflow with remote code execution
    potential (CVE-2013-6487).

  + XMPP :

  - Prevent spoofing of iq replies by verifying that the
    'from' address matches the 'to' address of the iq
    request (CVE-2013-6483).

  - Fix crash on some systems when receiving fake delay
    timestamps with extreme values (CVE-2013-6477).

  - Fix possible crash or other erratic behavior when
    selecting a very small file for your own buddy icon.

  - Fix crash if the user tries to initiate a voice/video
    session with a resourceless JID.

  - Fix login errors when the first two available auth
    mechanisms fail but a subsequent mechanism would
    otherwise work when using Cyrus SASL (pidgin.im#15524).

  - Fix dropping incoming stanzas on BOSH connections when
    we receive multiple HTTP responses at once
    (pidgin.im#15684).

  + Yahoo! :

  - Fix possible crashes handling incoming strings that are
    not UTF-8 (CVE-2012-6152).

  - Fix a bug reading a peer to peer message where a remote
    user could trigger a crash (CVE-2013-6481).

  + Plugins :

  - Fix crash in contact availability plugin.

  - Fix perl function Purple::Network::ip_atoi.

  - Add Unity integration plugin.

  + Windows specific fixes: (CVE-2013-6486, pidgin.im#15520,
    pidgin.im#15521, bgo#668154).

  - Drop pidgin-irc-sasl.patch, fixed upstream.

  - Obsolete pidgin-facebookchat: the package is no longer
    maintained and pidgin as built-in support for Facebook
    Chat.

  - Protect buildrequires for mono-devel with with_mono
    macro.

  - Add pidgin-gstreamer1.patch: Port to GStreamer 1.0. Only
    enabled on openSUSE 13.1 and newer.

  - On openSUSE 13.1 and newer, use gstreamer-devel and
    gstreamer-plugins-base-devel BuildRequires."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861019"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin / pidgin-branding-openSUSE packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:awesome-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bot-sentry-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compiz-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dynamic-wallpaper-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e17-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fcitx-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcin-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gconf2-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfxboot-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gio-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-menus-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk2-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gtk3-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hicolor-icon-theme-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:install-initrd-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-SuSE-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-runtime-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ksplash-qml-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ksplashx-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-advancednotifications");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-advancednotifications-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-aggregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-aggregator-bodyfetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-aggregator-bodyfetch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-aggregator-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-anhero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-anhero-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-auscrie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-auscrie-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-acetamide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-acetamide-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-adiumstyles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-adiumstyles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-autoidler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-autoidler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-autopaste");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-autopaste-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-birthdaynotifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-birthdaynotifier-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-chathistory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-chathistory-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-depester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-depester-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-embedmedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-embedmedia-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-herbicide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-herbicide-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-hili");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-hili-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-isterique");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-isterique-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-juick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-juick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-keeso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-keeso-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-lastseen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-lastseen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-metacontacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-metacontacts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-modnok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-modnok-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-nativeemoticons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-nativeemoticons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-otroid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-otroid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-p100q");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-p100q-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-rosenthal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-rosenthal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-shx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-shx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-standardstyles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-standardstyles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-vader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-vader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-velvetbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-velvetbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-xoox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-xoox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-xtazy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-xtazy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-zheet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-azoth-zheet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-bittorrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-bittorrent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique-hestia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique-hestia-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique-metida");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-blogique-metida-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-choroid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-choroid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-cstp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-cstp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dbusmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dbusmanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-deadlyrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-deadlyrics-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dolozhee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dolozhee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dumbeep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-dumbeep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-gacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-gacts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-glance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-glance-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-gmailnotifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-gmailnotifier-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-historyholder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-historyholder-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-hotsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-hotsensors-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-hotstreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-hotstreams-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-kbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-kbswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-kinotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-kinotify-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-knowhow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-knowhow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lackman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lackman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lastfmscrobble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lastfmscrobble-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-launchy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-launchy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lhtr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lhtr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-liznoo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-liznoo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-dumbsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-dumbsync-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-graffiti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-graffiti-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-mp3tunes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-lmp-mp3tunes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-fxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-fxb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-mu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-mu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-pdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-postrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-postrus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-seen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-monocle-seen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-musiczombie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-musiczombie-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-netstoremanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-netstoremanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-netstoremanager-googledrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-netstoremanager-googledrive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-networkmonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-networkmonitor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-newlife");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-newlife-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-otlozhu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-otlozhu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-pintab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-pintab-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-pogooglue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-pogooglue-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-popishu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-popishu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-autosearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-autosearch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-cleanweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-cleanweb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-fatape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-fatape-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-filescheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-filescheme-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-fua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-fua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-keywords");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-keywords-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks-delicious");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks-delicious-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks-readitlater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-poshuku-onlinebookmarks-readitlater-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-sb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-sb2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-secman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-secman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-secman-simplestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-secman-simplestorage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-seekthru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-seekthru-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-shaitan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-shaitan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-shellopen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-shellopen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-summary-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-syncer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-syncer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tabsessionmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tabsessionmanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tabslist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tabslist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-touchstreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-touchstreams-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-tpi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-vgrabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-vgrabber-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-vrooby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-vrooby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-xproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:leechcraft-xproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexo-1-0-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgarcon-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-bot-sentry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-bot-sentry-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-bot-sentry-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-facebookchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-facebookchat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-mrim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-mrim-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-openfetion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-openfetion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-openfetion-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-pack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-pack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-pack-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-pack-extras-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-sipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-sipe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-skype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-skype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-plugin-skype-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsocialweb-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxfce4ui-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lxde-common-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:midori-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-advanced-sound-notification-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-advanced-sound-notification-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-birthday-reminder-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-birthday-reminder-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-embeddedvideo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-facebookchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-facebookchat-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-guifications-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-guifications-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-mrim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-openfetion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-openfetion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-otr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-advanced-sound-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-advanced-sound-notification-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-birthday-reminder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-birthday-reminder-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-embeddedvideo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-embeddedvideo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-guifications");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-guifications-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-pack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-pack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-pack-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-plugin-skype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-sipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-sipe-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:plymouth-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:purple-plugin-pack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:purple-plugin-pack-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:skype4pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:splashy-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:susegreeter-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-presets-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:telepathy-haze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:telepathy-haze-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:telepathy-haze-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:telepathy-plugin-sipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:telepathy-plugin-sipe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-volman-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wallpaper-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfce4-notifyd-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfce4-panel-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfce4-session-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfce4-settings-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfce4-splash-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfdesktop-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xfwm4-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-qt-branding-basedonopensuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/17");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"bot-sentry-debugsource-1.3.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-debuginfo-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"finch-devel-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-branding-openSUSE-12.2-4.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-branding-upstream-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-debuginfo-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-devel-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-lang-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-meanwhile-debuginfo-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-bot-sentry-1.3.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-bot-sentry-debuginfo-1.3.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-bot-sentry-lang-1.3.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-facebookchat-1.69-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-facebookchat-debuginfo-1.69-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-mrim-0.1.28-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-mrim-lang-0.1.28-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-openfetion-0.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-openfetion-debuginfo-0.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-openfetion-lang-0.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-pack-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-pack-debuginfo-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-pack-extras-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-pack-extras-debuginfo-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-sipe-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-sipe-debuginfo-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-skype-0.0.1.rev624-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-skype-debuginfo-0.0.1.rev624-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-plugin-skype-lang-0.0.1.rev624-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpurple-tcl-debuginfo-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-advanced-sound-notification-debugsource-1.2.1-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-advanced-sound-notification-lang-1.2.1-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-birthday-reminder-debugsource-1.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-birthday-reminder-lang-1.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debuginfo-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-debugsource-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-devel-2.10.9-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-embeddedvideo-debugsource-1.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-facebookchat-1.69-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-facebookchat-debugsource-1.69-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-guifications-debugsource-2.16-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-guifications-lang-2.16-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-mrim-0.1.28-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-openfetion-0.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-openfetion-debugsource-0.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-4.0.0-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-debuginfo-4.0.0-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-otr-debugsource-4.0.0-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-advanced-sound-notification-1.2.1-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-advanced-sound-notification-debuginfo-1.2.1-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-birthday-reminder-1.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-birthday-reminder-debuginfo-1.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-embeddedvideo-1.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-embeddedvideo-debuginfo-1.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-guifications-2.16-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-guifications-debuginfo-2.16-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-pack-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-pack-debuginfo-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-pack-extras-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-plugin-skype-0.0.1.rev624-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-sipe-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pidgin-sipe-debugsource-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"purple-plugin-pack-debugsource-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"purple-plugin-pack-lang-2.7.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"skype4pidgin-debugsource-0.0.1.rev624-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"telepathy-haze-0.6.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"telepathy-haze-debuginfo-0.6.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"telepathy-haze-debugsource-0.6.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"telepathy-plugin-sipe-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"telepathy-plugin-sipe-debuginfo-1.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"PackageKit-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"awesome-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bot-sentry-debugsource-1.3.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"compiz-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dynamic-wallpaper-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"e17-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"epiphany-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"fcitx-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-debuginfo-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"finch-devel-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gcin-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gconf2-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gdm-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gfxboot-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gio-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnome-menus-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"grub2-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gtk2-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gtk3-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hicolor-icon-theme-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"install-initrd-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase3-SuSE-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-runtime-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdebase4-workspace-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdelibs4-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kdm-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ksplash-qml-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ksplashx-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-advancednotifications-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-advancednotifications-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-aggregator-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-aggregator-bodyfetch-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-aggregator-bodyfetch-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-aggregator-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-anhero-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-anhero-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-auscrie-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-auscrie-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-acetamide-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-acetamide-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-adiumstyles-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-adiumstyles-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-autoidler-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-autoidler-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-autopaste-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-autopaste-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-birthdaynotifier-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-birthdaynotifier-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-chathistory-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-chathistory-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-depester-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-depester-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-embedmedia-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-embedmedia-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-herbicide-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-herbicide-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-hili-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-hili-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-isterique-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-isterique-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-juick-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-juick-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-keeso-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-keeso-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-lastseen-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-lastseen-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-metacontacts-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-metacontacts-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-modnok-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-modnok-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-nativeemoticons-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-nativeemoticons-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-otroid-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-otroid-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-p100q-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-p100q-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-rosenthal-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-rosenthal-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-shx-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-shx-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-standardstyles-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-standardstyles-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-vader-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-vader-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-velvetbird-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-velvetbird-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-xoox-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-xoox-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-xtazy-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-xtazy-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-zheet-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-azoth-zheet-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-bittorrent-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-bittorrent-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-hestia-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-hestia-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-metida-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-blogique-metida-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-choroid-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-choroid-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-cstp-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-cstp-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dbusmanager-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dbusmanager-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-deadlyrics-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-deadlyrics-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-debugsource-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-devel-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dolozhee-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dolozhee-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dumbeep-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-dumbeep-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-gacts-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-gacts-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-glance-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-glance-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-gmailnotifier-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-gmailnotifier-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-historyholder-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-historyholder-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-hotsensors-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-hotsensors-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-hotstreams-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-hotstreams-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-kbswitch-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-kbswitch-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-kinotify-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-kinotify-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-knowhow-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-knowhow-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lackman-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lackman-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lastfmscrobble-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lastfmscrobble-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-launchy-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-launchy-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lemon-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lemon-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lhtr-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lhtr-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-liznoo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-liznoo-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-dumbsync-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-dumbsync-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-graffiti-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-graffiti-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-mp3tunes-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-lmp-mp3tunes-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-fxb-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-fxb-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-mu-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-mu-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-pdf-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-pdf-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-postrus-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-postrus-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-seen-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-monocle-seen-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-musiczombie-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-musiczombie-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-netstoremanager-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-netstoremanager-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-netstoremanager-googledrive-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-netstoremanager-googledrive-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-networkmonitor-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-networkmonitor-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-newlife-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-newlife-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-otlozhu-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-otlozhu-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-pintab-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-pintab-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-pogooglue-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-pogooglue-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-popishu-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-popishu-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-autosearch-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-autosearch-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-cleanweb-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-cleanweb-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-fatape-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-fatape-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-filescheme-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-filescheme-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-fua-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-fua-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-keywords-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-keywords-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-delicious-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-delicious-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-readitlater-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-poshuku-onlinebookmarks-readitlater-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-sb2-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-sb2-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-secman-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-secman-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-secman-simplestorage-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-secman-simplestorage-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-seekthru-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-seekthru-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-shaitan-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-shaitan-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-shellopen-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-shellopen-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-summary-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-summary-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-syncer-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-syncer-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tabsessionmanager-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tabsessionmanager-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tabslist-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tabslist-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-touchstreams-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-touchstreams-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tpi-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-tpi-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-vgrabber-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-vgrabber-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-vrooby-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-vrooby-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-xproxy-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"leechcraft-xproxy-debuginfo-0.6.0-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libexo-1-0-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgarcon-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-branding-openSUSE-13.1-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-branding-upstream-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-debuginfo-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-devel-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-lang-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-meanwhile-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-meanwhile-debuginfo-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-bot-sentry-1.3.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-bot-sentry-debuginfo-1.3.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-bot-sentry-lang-1.3.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-facebookchat-1.69-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-facebookchat-debuginfo-1.69-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-mrim-0.1.28-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-mrim-lang-0.1.28-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-openfetion-0.3-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-openfetion-debuginfo-0.3-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-openfetion-lang-0.3-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-pack-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-pack-debuginfo-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-pack-extras-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-pack-extras-debuginfo-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-sipe-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-sipe-debuginfo-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-skype-0.0.1.rev624-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-skype-debuginfo-0.0.1.rev624-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-plugin-skype-lang-0.0.1.rev624-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-tcl-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpurple-tcl-debuginfo-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsocialweb-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libxfce4ui-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lightdm-gtk-greeter-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lxde-common-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"midori-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-advanced-sound-notification-debugsource-1.2.1-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-advanced-sound-notification-lang-1.2.1-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-birthday-reminder-debugsource-1.7-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-birthday-reminder-lang-1.7-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-debuginfo-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-debugsource-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-devel-2.10.9-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-embeddedvideo-debugsource-1.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-facebookchat-1.69-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-facebookchat-debugsource-1.69-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-guifications-debugsource-2.16-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-guifications-lang-2.16-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-mrim-0.1.28-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-openfetion-0.3-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-openfetion-debugsource-0.3-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-4.0.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-debuginfo-4.0.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-otr-debugsource-4.0.0-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-advanced-sound-notification-1.2.1-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-advanced-sound-notification-debuginfo-1.2.1-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-birthday-reminder-1.7-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-birthday-reminder-debuginfo-1.7-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-embeddedvideo-1.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-embeddedvideo-debuginfo-1.2-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-guifications-2.16-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-guifications-debuginfo-2.16-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-pack-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-pack-debuginfo-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-pack-extras-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-plugin-skype-0.0.1.rev624-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-sipe-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pidgin-sipe-debugsource-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"plymouth-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"purple-plugin-pack-debugsource-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"purple-plugin-pack-lang-2.7.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"skype4pidgin-debugsource-0.0.1.rev624-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"splashy-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"susegreeter-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"systemd-presets-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"telepathy-haze-0.8.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"telepathy-haze-debuginfo-0.8.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"telepathy-haze-debugsource-0.8.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"telepathy-plugin-sipe-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"telepathy-plugin-sipe-debuginfo-1.17.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"thunar-volman-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wallpaper-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfce4-notifyd-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfce4-panel-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfce4-session-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfce4-settings-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfce4-splash-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfdesktop-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xfwm4-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"yast2-branding-basedonopensuse-13.1-3.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"yast2-qt-branding-basedonopensuse-13.1-3.4.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bot-sentry-debugsource / libpurple-plugin-bot-sentry / etc");
}
