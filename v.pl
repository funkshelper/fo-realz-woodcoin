#!/usr/bin/perl

# (C) 2015 The Bitcoin Foundation. You do not have, nor can you ever acquire
# the right to use, copy or distribute this software ; Should you use this
# software for any purpose, or copy and distribute it to anyone or in any
# manner, you are breaking the laws of whatever soi-disant jurisdiction, and
# you promise to continue doing so for the indefinite future. In any case,
# please always : read and understand any software ; verify any PGP signatures
# that you use - for any purpose. 

use strict;
use Graph::Easy;

# http://perldoc.perl.org/perldiag.html#keys-on-reference-is-experimental
no warnings "experimental";

my $version  = "99999 K ";

my %wot      = ();
my %map      = ();
my %banners  = ();
my %desc_map = ();
my $graph    = Graph::Easy->new();

my ($pdir, $sdir, $wdir)       = "";
my (@pfiles, @sfiles, @wfiles) = ();

sub set_files {
  my ($dir) = @_;
  if(!-d $dir) {
    print "$dir directory does not exist. Refer to help.\n";
    print "See 'init' or 'sync' commands.\n";
    print short_help("t"); exit -1;
  }
  my @a = `ls $dir | sort`;
  return wash(@a);
}

sub wash { my (@a)=@_; my @b; foreach(@a) {chomp($_); push @b, $_;} return @b; }

sub init {
  my ($URL, $pd, $sd) = @_;

  if($URL && $pd && $sd) {
    if(!-d $pd) { `mkdir -p $pd`; sync_all_vpatches($URL, $pd); }
    else { print "$pd dir exists! Skipping initial Vpatch sync\n"; }
    if(!-d $sd) { `mkdir -p $sd`; sync_seals($URL, $sd); }
    else { print "$sd dir exists! Skipping intial Seal sync\n"; }
  }
}

sub build_wot {
  my $uid, my $banner, my $keyid, my $fp;
  foreach my $pubkey (@wfiles) {
    my $res = `gpg --logger-fd 1 --keyid-format=long --import $wdir/$pubkey`;
    $uid = $1 if $pubkey =~ /(.*)\.asc/; chomp($uid);
    $banner = $1 if $res =~ /\"(.*)\"/; chomp($banner);
    $keyid = $1 if $res =~ /key (.*)\:/; chomp($keyid);
    my $res_fp = `gpg --logger-fd 1 --fingerprint $keyid`;
    $fp = $1 if $res_fp =~ /Key fingerprint = (.*)/; $fp =~ s/\s+//g;
    $wot{$uid} = { fp => $fp, banner => $banner };
  }
}

sub validate_seals {
  my $seal_key, my $uid, my $fp, my $patch, my %sig;
  foreach my $patch (@pfiles) {
    foreach my $seal (@sfiles) {
      $seal_key = $1 if $seal =~ /(.*)\..*\..*/;
      if($patch =~ /$seal_key/) {
        if(not exists $banners{$patch} && $patch ne "") {
          $banners{$patch} = $patch;
          %sig = ();
        }
        my @res = `gpg --logger-fd 1 --verify $sdir/$seal $pdir/$patch`;
        foreach my $r (@res) {
          $fp = $1 if $r =~ /Primary key fingerprint: (.*)/; $fp =~ s/\s+//g;
          foreach my $uidkey (sort keys %wot) {
            if($wot{$uidkey}{fp} eq $fp) {
              $uid = $uidkey;
              last;
            }
          }
        }
        my $verified = "";
        foreach my $r (@res) {
          if($r =~ /Good signature/ && $uid ne "") {
            $sig{$wot{$uid}{fp}} = $uid;
            $banners{$patch} = {%sig};
            $verified = "true";
            last;
          }
        }
        if($verified ne "true") {
          my $border = "-----------------------------------------" .
          "-----------------------------------------";
          print "$border\n";
          print "WARNING: $seal is an INVALID seal for $patch!\n";
          my $msg = "Check that this user is in your WoT, and that this key " .
          "has not expired.\nOtherwise remove the invalid seal from your " .
          "SEALS directory.";
          print "$msg\n";
          print "$border\n";
          die;
        }
        $verified = "";
      }
    }
  }
}

sub build_map {
  my %vpdata;
  foreach my $pfile (@pfiles) {
    $map{$pfile} = $pfile;
    my @patch = `cat $pdir/$pfile`;
    my $src_file = "", my $ante_hash = "", my $desc_hash = "";
    foreach my $p (@patch) {
      $src_file = $1, $ante_hash = $2 if $p =~ /^--- (.*) (.*)/;
      $desc_hash = $1 if $p =~ /^\+\+\+ .* (.*)/;
      if($src_file && $ante_hash && $desc_hash) {
        $vpdata{$src_file} = { a => $ante_hash, b => $desc_hash };
        $map{$pfile} = {%vpdata};
      }
    }
    %vpdata = ();
  }
  return %map;
}

sub roots {
  my @roots;
  foreach my $pfile (@pfiles) { 
    my %ante = antecedents($pfile);
    push @roots, $pfile if !%ante;
  }
  return @roots;
}

sub leafs {
  my @leafs;
  foreach my $pfile (@pfiles) {
    my %desc = descendants($pfile);
    push @leafs, $pfile if !%desc;
  }
  return @leafs;
}

sub traverse_desc {
  my (%st) = @_;
  my %desc;
  foreach my $k (keys %map) {
    my @tmp = ();
    while(my ($src_file, $ref) = each $map{$k}) {
      while(my ($sf, $r) = each %st) {
        if($src_file eq $sf &&
           $ref->{a} eq $r->{b} &&
           $ref->{a} ne "false") {
          push @tmp, $sf;
          $desc{$k} = [@tmp];
        }
      }
    }
  }
  return %desc;
}

sub traverse_ante {
  my (%st) = @_;
  my %ante;
  foreach my $k (keys %map) {
    my @tmp = ();
    while(my ($src_file, $ref) = each $map{$k}) {
      while(my ($sf, $r) = each %st) {
        if($src_file eq $sf &&
           $ref->{b} eq $r->{a} &&
           $ref->{b} ne "false") {
          push @tmp, $sf;
          $ante{$k} = [@tmp];
        }
      }
    }
  }
  return %ante;
}

sub search_map {
  my ($search_key) = @_;
  if(exists $map{$search_key}) {
    return %{$map{$search_key}};
  } else {
    die "Error! Could not find vpatch \"$search_key\" in $pdir\n";
  }
}

sub antecedents {
  my ($vpatch) = @_;
  return traverse_ante(search_map($vpatch));
}

sub descendants {
  my ($vpatch) = @_;
  return traverse_desc(search_map($vpatch));
}

sub get_signatories {
  my ($vpatch) = @_;
  my @sigs;
  foreach my $k (keys %banners) {
    while(my ($fp, $uid) = each $banners{$k}) {
      push @sigs, $uid if $vpatch eq $k;
    }
  }
  push @sigs, "WILD" if !@sigs;
  return "(" . join(', ', sort @sigs) . ")";
}

sub build_flow {
  my @flow = ();
  my @roots = roots();
  foreach my $root (@roots) {
    my %desc = descendants($root);
    my @dkeys = keys %desc;
    $desc_map{$root} = [@dkeys]; 
    get_all_descendant_nodes($root, sort @dkeys);
    @flow = toposort(%desc_map);
  }
  return @flow;
}

sub get_all_descendant_nodes {
  my ($origin, @vpatch) = @_;
  my %desc = ();
  foreach my $vp (@vpatch) {
    %desc = descendants($vp);
    if(keys %desc) {
      my @dkeys = keys %desc;
      $desc_map{$vp} = [@dkeys];
      get_all_descendant_nodes($vp, sort @dkeys);
    }
    if(!%desc) {
      $desc_map{$vp} = [];
    }
  }
  return %desc_map;
}

sub toposort {
  my (%unsorted) = @_;
  my $acyclic = "", my $flag = "f", my @flow = ();
  while(%unsorted) {
    $acyclic = "false";
    foreach my $node (sort keys %unsorted) {
      my @edges = @{$unsorted{$node}};
      foreach my $edge (@edges) {
        $flag = "t" and last if exists $unsorted{$edge};
      }
      if($flag ne "t") {
        $acyclic = "true";
        delete $unsorted{$node};
        push @flow, $node;
      }
      $flag = "";
    }
    if(!$acyclic eq "true") { print "Cyclic Graph!\n"; exit -1; }
  }
  return reverse @flow;
}

sub press_vpatches {
  my ($p, @flow) = @_;
  my @press = @{$p};
  my $v = 1 and shift @press if $press[0] =~ /v|verbose/i;
  `mkdir -p $press[0]`;
  foreach my $vp (@flow) {
    if($v) {
      my @out = `patch -E --dir $press[0] -p1 < $pdir/$vp 2>&1`;
      print "$vp\n";
      foreach my $o (@out) { print "  $o"; }
    } else {
      print "pdir: $pdir\n"; #XXX
      `patch -E --dir $press[0] -p1 < $pdir/$vp`;
    }
    last if $vp eq $press[1];
  }
}

sub sync_seals {
  my ($URL, $out) = @_;
  if(!-d $out) { `mkdir -p $out`; }
  my $wget = "wget -q -r -nd -N --no-parent " .
  "--reject \"index.html*\"  $URL/v/seals/ -P $out";
  `$wget`;
  print "Seal sync complete to \"$out\"\n";
}

sub sync_vpatches {
  my ($URL, $out, @sync) = @_;
  my $wget = "";
  if(!-d $out) { `mkdir -p $out`; }
  foreach my $vpatch (@sync) {
    $wget = "wget -q -r -nd -N --no-parent " .
    "--reject \"index.html*\"  $URL/v/patches/$vpatch -P $out";
    `$wget`;
    print "$vpatch sync complete to \"$out\"\n";
  }
}

sub sync_all_vpatches {
  my ($URL, $out) = @_;
  if(!-d $out) { `mkdir -p $out`; }
  my $wget = "wget -q -r -nd -N --no-parent " .
  "--reject \"index.html*\"  $URL/v/patches/ -P $out";
  `$wget`;
  print "Full vpatch sync complete to \"$out\"\n";
}

sub sync_everything {
  my ($URL, $pd, $sd) = @_;
  sync_all_vpatches($URL, $pd);
  sync_seals($URL, $sd);
}

sub build_desc_full_graph {
  $graph->set_attributes("graph",
  {
    font  => "monospace",
    label => "..::[ The Bitcoin Foundation: Vpatch Graph ]::.."
  });
  $graph->set_attributes("node",
  {
    linkbase => "http://thebitcoin.foundation/v/patches/",
    autolink => "name",
    color    => "blue"
  });
  my @roots = roots();
  foreach my $root (@roots) {
    my $node = $graph->add_node($root);
    $node->set_attribute("title", "Signed By: " . get_signatories($root));
    my %desc = descendants($root);
    my @dkeys = keys %desc;
    add_desc_edges($root, @dkeys);
    my @sn = $graph->source_nodes();
    add_desc_src_files($sn[0]);
  }
}

sub add_desc_edges {
  my ($origin, @vpatch) = @_;
  my %desc = ();
  foreach my $vp (@vpatch) {
    %desc = descendants($vp);
    my $node = $graph->add_node($vp);
    my $sigs = get_signatories($vp);
    $node->set_attribute("title", "Signed By: $sigs");
    $graph->add_edge_once($origin, $vp);
    if(keys %desc) {
      my @dkeys = sort keys %desc;
      add_desc_edges($vp, @dkeys);
    }
  }
}

sub add_desc_src_files {
  my ($node) = @_;
  my %desc = descendants($node->name());
  my @suc = $node->successors();
  foreach my $s (@suc) {
    my $name = $s->name();
    my @edges = $node->edges_to($s);
    foreach my $e (@edges) {
      $e->set_attribute("title", "[ " . join('; ', sort @{$desc{$name}}) . " ]");
      add_desc_src_files($s);
    }
  }
}

sub rank_leafs_gviz {
  build_desc_full_graph();
  my $gviz = $graph->as_graphviz();
  my @leafs = leafs();
  $gviz =~ s/GRAPH_0/VPATCH_GRAPH/;
  $gviz =~ s/rankdir=LR/rankdir=BT,ranksep=1.00,nodesep=.15/;
  $gviz =~ s/}$//;
  $gviz .= "  { rank=same; ";
  foreach my $l (@leafs) {
    $gviz .= "\"$l\" ";
  }
  $gviz .= "}\n}";
  return $gviz;
}

sub print_graph {
  my ($graph, @gv) = @_;
  if(!@gv) {
    print "$graph\n";
  } elsif($#gv eq 1) {
    open(my $fh, ">", $gv[0]); print $fh "$graph\n";
    close($fh);
    print "Printed Graphviz dot file to $gv[0]\n";
    my @which = `which dot`; chomp($which[0]);
    if($which[0] =~ /dot/) {
      `$which[0] -Tsvg $gv[0] > $gv[1]`;
    } else {
      print "`dot` binary not found, check if 'graphviz' is installed\n";
    }
    print "Executed `dot` and built svg html output file: $gv[1]\n";
  } else {
    open(my $fh, ">", $gv[0]); print $fh "$graph\n";
    close($fh);
    print "Printed Graphviz dot file to $gv[0]\n";
  }
}

sub get_mirrors {
  my ($out) = @_;
  my @mirror_sigs = ();
  if(!-d $out) { `mkdir -p $out`; }
  my $wget = "wget -q -r -nd -N --no-parent " .
  "--reject \"index.html*\" -A 'mirrors.*' http://thebitcoin.foundation/v/ -P $out";
  `$wget`;

  my @sigs = `ls $out | sort`;
  @sigs = wash(@sigs);
  foreach my $sig (@sigs) {
    my $who = $1 if $sig =~ /.*\..*\.(.*)\..*/;
    my @res = `gpg --logger-fd 1 --verify $out/$sig $out/mirrors.txt`;
    foreach my $r (@res) {
      if($r =~ /Good signature/) {
       push @mirror_sigs, $who;
       next;
      }
    }
  }
  return @mirror_sigs;
}

sub print_mirrors {
  my ($out) = @_;
  my @mirror_sigs = get_mirrors($out);

  if(-d $out) {
    my @mirrors = `cat $out/mirrors.txt`;
    print "Mirrors signed by ("  . join(', ', sort @mirror_sigs) . "):\n";
    foreach(@mirrors) { chomp($_); print "$_\n"; }
  }
}

sub print_roots {
  my @r = roots();
  foreach(@r) {
    print "Root: $_ " . get_signatories($_) . "\n";
  }
}

sub print_leafs {
  my @l = leafs();
  foreach(@l) {
    print "Leaf: $_ " . get_signatories($_) . "\n";
  }
}

sub print_wot {
  my ($finger) = @_;
  if(%wot) {
    foreach my $uid (sort keys %wot) {
      if(!$finger) {
        print "$uid:$wot{$uid}{fp}:$wot{$uid}{banner}\n";
      } else {
        print "$uid-" . substr($wot{$uid}{fp}, -16) .
              ":$wot{$uid}{fp}:$wot{$uid}{banner}\n";
      }
    }
  }
}

sub print_antecedents {
  my ($vpatch) = @_;
  my %ante = antecedents($vpatch);
  my $sigs;
  foreach my $a (sort keys %ante) {
    $sigs = get_signatories($a);
    print "Antecedent: $a $sigs [ " . join('; ', sort @{$ante{$a}}) . " ]\n";
  }
}

sub print_descendants {
  my ($vpatch) = @_;
  my %desc = descendants($vpatch);
  my $sigs;
  foreach my $d (sort keys %desc) {
    $sigs = get_signatories($d);
    print "Descendant: $d $sigs [ " . join('; ', sort @{$desc{$d}}) . " ]\n";
  }
}

sub print_flow {
  my (@flow) = @_;
  foreach(@flow) { print "$_ " . get_signatories($_) . "\n"; }
}

sub get_version {
  my $version_text = << "END_VERSION_TEXT";
################################################################################
#               ..::[ The Bitcoin Foundation: V ]::..                          #
#                                                                              #
#     Version: $version                                                        #
#      Author: mod6                                                            #
# Fingerprint: 0x027A8D7C0FB8A16643720F40721705A8B71EADAF                      #
#                                                                              #
################################################################################
END_VERSION_TEXT
  return $version_text;
}

sub short_help {
  my ($flag) = @_;
  my $short_help = << "END_SHORT_HELP";
################################################################################
#               ..::[ The Bitcoin Foundation: V ]::..                          #
#                                                                              #
#     Version: $version                                                        #
#      Author: mod6                                                            #
# Fingerprint: 0x027A8D7C0FB8A16643720F40721705A8B71EADAF                      #
#                                                                              #
#       Usage: v.pl                                                            #
#              (m  | mirrors) (<output_dir>)                                   #
#              (i  | init) (mirror_url) [(<pdir> <sdir>)]                      #
#              (wd | wotdir) (<wotdir>)                                        #
#              (pd | patchdir) (<patchdir>)                                    #
#              (sd | sealdir) (<sealdir>)                                      #
#              (w  | wot) [ finger ]                                           #
#              (r  | roots)                                                    #
#              (l  | leafs)                                                    #
#              (f  | flow)                                                     #
#              (p  | press) (<press_dir> <head>)                               #
#              (ss | sync-seals) (<mirror_url> <sdir>)                         #
#              (sv | sync-vpatches) (<mirror_url> <pdir> <vpatches>... )       #
#              (sa | sync-all-vpatches) (<mirror_url> <pdir>)                  #
#              (se | sync-everything) (<mirror_url> <pdir> <sdir>)             #
#              (a  | ante | antecedents) (<vpatch>)                            #
#              (d  | desc | descendants) (<vpatch>)                            #
#              (g  | graph) (<output_dotfile> [<output_svg_html_file>])        #
#              (v  | version)                                                  #
#              (h  | ? | help)                                                 #
#                                                                              #
END_SHORT_HELP
  my $l = "########################################" .
          "########################################\n";
  if($flag) { $short_help .= $l; }
  return $short_help;
}

sub long_help {
  print short_help();
  my $long_help = << "END_LONG_HELP";
#  Commands:                                                                   #
#     m, mirrors (<output_dir>)                                                #
#        Will attempt to retrieve, cryptographically verify and print entries  #
#        in this list for usage in other commands.  Mirrors command my only be #
#        invoked by itself. [See: sync-seals, sync-vpatches, sync-everything]  #
#                                                                              #
#     i, init (<mirror_url>) [(<pdir> <sdir>)]                                 #
#        init should be run as the first command executed with V. init only    #
#        requires one option: <mirror_url>.  The <pdir> and <sdir> options are # 
#        optional.  Use these if you want to override the default Vpatches and #
#        Seals directories in that exact order.                                #
#                                                                              #
#        Defaults: "~/.wot", "patches" (in present working directory) and      #
#        "~/.seals" will be used as defaults.  WoTs pubkeys can not be sync'd  #
#        these need to be placed in the WoT directory manually.                #
#                                                                              #
#        Set <mirror_url> to one of the signed URLs in the PGP signed mirrors  #
#        list at: http://thebitcoin.foundation/v/mirrors.txt                   #
#                                                                              #
#    wd, wotdir (<wotdir>)                                                     #
#        Given the required option <wotdir>, overrides the default wotdir      #
#        ( ~/.wot ) containing PGP public keys.                                #
#                                                                              #
#    pd, patchdir (<patchdir>)                                                 #
#        Given required option of <patchdir>, overrides the default            #
#        patchdir ( ./patches ) containing vpatch files.                       #
#                                                                              #
#    sd, sealdir (<sealdir>)                                                   #
#        Given required option of <sealdir>, overrides the default sealdir     #
#        ( ~/.seals ) containing PGP detached signatures of vpatch files.      #
#                                                                              #
#    w, wot [ finger ]                                                         #
#        Loads PGP public keys from wotdir and prints the WoT to stdout        #
#                                                                              #
#    r, roots                                                                  #
#        Finds the root vpatches (which have no antecedents) and prints them   #
#        to stdout.                                                            #
#                                                                              #
#    l, leafs                                                                  #
#        Finds the leaf vpatches (which have no descendants) and prints them   #
#        to stdout.                                                            #
#                                                                              #
#    f, flow                                                                   #
#        Prints the topological flow of vpatches based on precedence.          #
#                                                                              #
#    p, press (<press_dir> <head>)                                             #
#        Given required options <press_dir> output directory and <vpatch>      #
#        press will apply vpatches in topologicial order up through the        #
#        supplied (head) vpatch.  Will print patching output if 'verbose' flag #
#        is supplied immediately after ( p | press ) option.                   #
#        See: ( f | flow ) to view the topological ordering.                   #
#                                                                              #
#    ss, sync-seals (<mirror_url> <sdir>)                                      #
#        Given required options of <mirror_url> and output directory <sdir>    #
#        will pull all of the available seal files from the given mirror into  #
#        output directory.                                                     #
#                                                                              #
#    sv, sync-vpatches (<mirror_url> <pdir> <vpatch>... )                      #
#        Given required options of <mirror_url> and output directory <pdir>    #
#        will pull the requested vpatch(s) from the given mirror into output   #
#        directory.                                                            #
#                                                                              #
#    sa, sync-all-vpatches (<mirror_url> <pdir>)                               #
#        Given required options of <mirror_url> and output directory <pdir>    #
#        will pull all available vpatches from the given mirror into output    #
#        directory.                                                            #
#                                                                              #
#    se, sync-everything (<mirror_url> <pdir> <sdir>)                          #
#        Given required options of <mirror_url>, <pdir>, and <sdir>;           #
#        sync-everything will pull all of the available seals and vpatches     #
#        available at the given mirror.                                        #
#                                                                              #
#    a, ante, antecedents (<vpatch>)                                           #
#        Finds the antecedents of a given vpatch and prints the results to     #
#        stdout                                                                #
#                                                                              #
#    d, desc, descendants (<vpatch>)                                           #
#        Finds the descendants of a given vpatch and prints the results to     #
#        stdout                                                                #
#                                                                              #
#    g, graph (<output_dotfile> [<output_svg_html_file>])                      #
#        Builds a complete directed GraphViz graph of all vpatches from a      #
#        topological flow and prints the Dot language output to file.  If the  #
#        output_svg_html_file argument is supplied the V will attempt to parse #
#        the output_dotfile into an html file; Requires having separately      #
#        installed 'graphviz' ahead of time.                                   #
#                                                                              #
#    v, version                                                                #
#        Prints the version message.                                           #
#                                                                              #
#    h, ?, help                                                                #
#        Prints this full help message.                                        #
#                                                                              #
################################################################################
END_LONG_HELP
  return $long_help;
}

sub main {
  my $cmd;
  if(@ARGV > 0) { $cmd = shift @ARGV; }
  else { print "Unknown or missing option!\n"; print short_help("t"); exit; }

  my $home = `echo \$HOME`; chomp($home);
  $wdir = "$home/.wot";
  $pdir = "patches";
  $sdir = "$home/.seals";

  if(($cmd =~ /^m$|^mirrors$/i            ||
      $cmd =~ /^i$|^init$/i               ||
      $cmd =~ /^wd$|^wotdir$/i            ||
      $cmd =~ /^pd$|^patchdir$/i          ||
      $cmd =~ /^sd$|^sealdir$/i           ||
      $cmd =~ /^p$|^press$/i              ||
      $cmd =~ /^ss$|^sync-seals$/i        ||
      $cmd =~ /^sv$|^sync-vpatches$/i     ||
      $cmd =~ /^sa$|^sync-all-vpatches$/i ||
      $cmd =~ /^sa$|^sync-all-vpatches$/i ||
      $cmd =~ /^se$|^sync-everything$/i   ||
      $cmd =~ /^a$|^ante$|^antecedents$/i ||
      $cmd =~ /^d$|^desc$|^descendants$/i ||
      $cmd =~ /^g$|^graph$/i) && !@ARGV) {
    print "Option \"$cmd\" requires arguments!\n";
    print short_help("t"); exit;
  }

  my @tmp = ();
  while(@ARGV > 0) {
    if($ARGV[0] =~ /^wd$|^wotdir$/) {
      shift @ARGV; $wdir = shift @ARGV; next;
    } elsif($ARGV[0] =~ /^pd$|^patchdir$/) {
      shift @ARGV; $pdir = shift @ARGV; next;
    } elsif($ARGV[0] =~ /^sd$|^sealdir$/) {
      shift @ARGV; $sdir = shift @ARGV; next;
    } else {
      push @tmp, shift @ARGV;
    }
  }
  @ARGV = @tmp;

  @wfiles = set_files($wdir);
  build_wot();

  if($cmd =~ /^h$|^help$|^\?$/) { print long_help(); exit; }
  if($cmd =~ /^i$|^init$/) {
    if(@ARGV == 1) {
      init(@ARGV, $pdir, $sdir); exit;
    } elsif(@ARGV == 3) {
      $sdir = pop @ARGV; $pdir = pop @ARGV;
      init(@ARGV, $pdir, $sdir); exit;
    } else {
      print "Incorrect number of arguments passed to init!\n";
      print short_help("t"); exit;
    }
  }

  if($cmd =~ /^m$|^mirrors$/) { print_mirrors(@ARGV); exit; }
  if($cmd =~ /^w$|^wot$/) { print_wot(@ARGV); exit; }
  if($cmd =~ /^v$|^version$/) { print get_version(); exit; }

  @pfiles = set_files($pdir);
  @sfiles = set_files($sdir);

  validate_seals();
  build_map();

  if   ($cmd =~ /^r$|^roots$/) { print_roots(); }
  elsif($cmd =~ /^l$|^leafs$/) { print_leafs(); }
  elsif($cmd =~ /^f$|^flow$/) { print_flow(build_flow()); }
  elsif($cmd =~ /^p$|^press$/) {
    if(@ARGV < 2) {
      print "$cmd requires two arguments: (<press_dir> <head>)\n\n";
      print short_help("t"); }
    else { press_vpatches(\@ARGV, build_flow()); } }
  elsif($cmd =~ /^ss$|^sync-seals$/) {
    if(@ARGV < 2) {
      print "$cmd requires two arguments: (<mirror_url> <sdir>)\n\n";
      print short_help("t"); }
    else { sync_seals(@ARGV); } }
  elsif($cmd =~ /^sv$|^sync-vpatches$/) {
    if(@ARGV < 3) {
      print "$cmd requires three arguments: " .
      "(<mirror_url> <pdir> <vpatch>... )\n\n"; print short_help("t"); }
    else { sync_vpatches(@ARGV); } }
  elsif($cmd =~ /^sa$|^sync-all-vpatches$/) {
    if(@ARGV < 2) {
      print "$cmd requires two arguments: " .
      "(<mirror_url> <pdir>)\n\n"; print short_help("t"); }
    else { sync_all_vpatches(@ARGV); } }
  elsif($cmd =~ /^se$|^sync-everything$/) {
    if(@ARGV < 3) {
      print "$cmd requires three arguments: " .
      "(<mirror_url> <pdir> <sdir>)\n\n"; print short_help("t"); }
    else { sync_everything(@ARGV); } }
  elsif($cmd =~ /^a$|^ante$|^antecedents$/) { print_antecedents(@ARGV); }
  elsif($cmd =~ /^d$|^desc$|^descendants$/) { print_descendants(@ARGV); }
  elsif($cmd =~ /^g$|^graph$/) { print_graph(rank_leafs_gviz(), @ARGV); }
  else { print "Unknown option: \"$cmd\"\n"; print short_help("t"); }
}

main();
