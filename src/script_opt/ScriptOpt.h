// See the file "COPYING" in the main distribution directory for copyright.

// Classes for controlling/orchestrating script optimization & compilation.

#pragma once

#include <string>
#include <optional>

#include "zeek/Func.h"
#include "zeek/Expr.h"
#include "zeek/Scope.h"

namespace zeek { struct Options; }

namespace zeek::detail {


// Flags controlling what sorts of analysis to do.

struct AnalyOpt {
	// Whether to analyze scripts.
	bool activate = false;

	// If true, dump out transformed code: the results of reducing
	// interpreted scripts, and, if optimize is set, of then optimizing
	// them.  Always done if only_func is set.
	bool dump_xform = false;

	// If non-nil, then only analyze the given function/event/hook.
	std::optional<std::string> only_func;

	// If true, do global inlining.
	bool inliner = false;

	// If true, generate C++;
	bool gen_CPP = false;

	// If true, generate C++ for those script bodies that don't already
	// have generated code, in a form that enables later compiles to
	// take advantage of the newly-added elements.  Only use for generating
	// a zeek that will always include the associated scripts.
	bool update_CPP = false;

	// If true, generate C++ for those script bodies that don't already
	// have generated code.  The added C++ is not made available for
	// later generated code, and will work for a generated zeek that
	// runs without including the associated scripts.
	bool add_CPP = false;

	// If true, use C++ bodies if available.
	bool use_CPP = false;

	// Same, but complain about missing bodies.
	bool force_use_CPP = false;

	// If true, report on available C++ bodies.
	bool report_CPP = false;

	// If true, report which functions are directly and indirectly
	// recursive, and exit.  Only germane if running the inliner.
	bool report_recursive = false;

	// If non-zero, looks for variables that are used-but-possibly-not-set,
	// or set-but-not-used.
	//
	// If > 1, also reports on uses of uninitialized record fields and
	// analyzes nested records in depth.  Warning: with the current
	// data structures this greatly increases analysis time.
	int usage_issues = 0;
};

extern AnalyOpt analysis_options;


class ProfileFunc;

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;

// Info we need for tracking an instance of a function.
class FuncInfo {
public:
	FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body);

	ScriptFunc* Func() const		{ return func.get(); }
	const ScriptFuncPtr& FuncPtr() const	{ return func; }
	const ScopePtr& Scope() const		{ return scope; }
	const StmtPtr& Body() const		{ return body; }
	ProfileFunc* Profile() const		{ return pf.get(); }
	const std::string& SaveFile() const	{ return save_file; }

	void SetBody(StmtPtr new_body)	{ body = std::move(new_body); }
	void SetProfile(std::unique_ptr<ProfileFunc> _pf);
	void SetSaveFile(std::string _sf)	{ save_file = std::move(_sf); }

	bool Skip() const	{ return skip; }
	void SetSkip()		{ skip = true; }

protected:
	ScriptFuncPtr func;
	ScopePtr scope;
	StmtPtr body;
	std::unique_ptr<ProfileFunc> pf;

	// If we're saving this function in a file, this is the name
	// of the file to use.
	std::string save_file;

	// Whether to skip compiling this function.
	bool skip = false;
};


// We track which functions are definitely not recursive.  We do this
// as the negative, rather than tracking functions known to be recursive,
// so that if we don't do the analysis at all (it's driven by inlining),
// we err on the conservative side and assume every function is recursive.
extern std::unordered_set<const Func*> non_recursive_funcs;

// Analyze a given function for optimization.
extern void analyze_func(ScriptFuncPtr f);

// Analyze all of the parsed scripts collectively for optimization.
extern void analyze_scripts();


// Used for C++-compiled scripts to signal their presence, by setting this
// to a non-empty value.
extern void (*CPP_init_hook)();


} // namespace zeek::detail
