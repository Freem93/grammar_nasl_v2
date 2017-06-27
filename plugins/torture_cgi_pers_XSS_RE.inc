# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# torture_cgi_pers_XSS_pat.inc
# $Revision: 1.6 $
#

global_var	global_patterns, pers_xss_regex, refl_xss_patterns;

# Do NOT change order, do NOT change or remove the parenthesis.
# see torture_cgi_persistent_XSS.nasl

pers_xss_regex = make_list(
 "<script>alert\(([PG])([A-F0-9]+)\);</script>",
 "<BODY +ONLOAD=alert\(([PG])([A-F0-9]+)\)>",
 "<([PG])([A-F0-9]+)>>",
 ">([PG])([A-F0-9]+)<<"
);

refl_xss_patterns = make_list(
  'RE:script>alert\\([1-4]?[0-9][0-9]\\);?</script',
#  "ST:<script>alert(42);</script>",
#  'ST:"><script>alert(42)</script>"',
  'RE:<BODY ONLOAD=alert\\([1-4][0-9][0-9]\\)>',
#  'ST:<IMG SRC="javascript:alert(42);">',
  'RE:javascript:alert\\([1-4]?[0-9][0-9]\\)',
  'ST:<script\n>alert(110);</script\n>',
  'RE:<<foo"bar\'[0-9]*>>',
  'RE:>>foo"bar\'[0-9]*<<',
  "ST:<b foo=&{alert(206)};>",

#  'RE:^([^"]|"([^"\\]|\\[\\"])*")*<script>alert\\(42\\);</script>',
#  'RE:[^\\\\]"><script>alert\\(42\\);</script>',
#  'RI:<[A-Z]+[^>]*[ \t]+(SRC|HREF)="javascript:alert\\(42\\)',
  'RE:<[a-zA-Z]+[^>]* onmouseover=alert\\([1-4]?[0-9][0-9]\\)',
  "RE:<script *> *alert\([1-4]?[0-9][0-9]\); *</script *>",
  "RE:< *script *> *alert\([1-4]?[0-9][0-9]\); *</ *script *>",
  "RE:\+ADw-script\+AD4-alert([1-4]?[0-9][0-9])\+ADw-/script\+AD4-|<script>alert\([1-4]?[0-9][0-9]\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\((.[1-4])?.[0-9].[0-9].\).<./.s.c.r.i.p.t.>",
  'RE:<[^"]*("[^"]*")*[^"]*"" onfocus="alert\\([1-4]?[0-9][0-9]\\)"'
);
