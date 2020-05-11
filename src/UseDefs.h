// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "Obj.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>

// UseDefs track which variables (identifiers) are used at or subsequent
// to a given (reduced) Statement.  They allow us to determine unproductive
// variable assignments (both to warn the user, and to prune temporaries)
// and also access to globals (so we know which ones need to be synchronized
// across function calls).

class Expr;
class Stmt;
class ID;

typedef std::unordered_set<const ID*> use_def_set;

class UseDefSet;
typedef IntrusivePtr<UseDefSet> UDs;

class UseDefSet : public BroObj {
public:
	UseDefSet() : BroObj()	{ }
	UseDefSet(const UDs& uds) : BroObj()
		{ Replicate(uds); }

	void Replicate(const IntrusivePtr<UseDefSet>& from)
		{
		use_defs = from->use_defs;
		}

	bool HasID(const ID* id)
		{ return use_defs.find(id) != use_defs.end(); }

	void Add(const ID* id)		{ use_defs.insert(id); }
	void Remove(const ID* id)	{ use_defs.erase(id); }

	const use_def_set IterateOver() const	{ return use_defs; }

	void Dump() const;
	void DumpNL() const	{ Dump(); printf("\n"); }

protected:
	std::unordered_set<const ID*> use_defs;
};

class Reducer;

class UseDefs {
public:
	UseDefs(Stmt* body, Reducer* rc);
	~UseDefs();

	void Analyze();

	bool HasUsage(const Stmt* s) const
		{ return use_defs_map.find(s) != use_defs_map.end(); }

	UDs GetUsage(const Stmt* s) const	{ return FindUsage(s); }
	UDs GetUsageAfter(const Stmt* s) const	{ return FindSuccUsage(s); }

	// Removes assignments corresponding to unused temporaries.
	// In the process, reports on locals that are assigned
	// but never used.
	void RemoveUnused();

	void Dump();

protected:
	// Makes one pass over the statements, removing assignments
	// corresponding to temporaries.  "iter" is the iteration
	// count of how often we've done such passes, with the first
	// pass being numbered 1.
	//
	// Returns true if something was removed, false if not.
	bool RemoveUnused(int iter);

	// For a given identifier defined at a given statement, returns
	// whether it is unused.  If "report" is true, also reports
	// this fact.
	bool CheckIfUnused(const Stmt* s, const ID* id, bool report);

	// Propagates use-defs (backward) across statement s,
	// given its successor's UDs.
	//
	// succ_stmt is the successor statement to this statement.
	// We only care about it for potential assignment statements,
	// (see the "successor" map below).
	//
	// second_pass is true when we revisit a set of statements
	// to propagate additional UDs generated by loop confluence.
	// If true, it prevents some redundant bookkeeping from occurring.
	UDs PropagateUDs(const Stmt* s, UDs succ_UDs, const Stmt* succ_stmt,
				bool second_pass);

	UDs FindUsage(const Stmt* s) const;
	UDs FindSuccUsage(const Stmt* s) const;

	// Returns a new use-def corresponding to the variables
	// referenced in e.
	UDs ExprUDs(const Expr* e);

	// Helper method that adds in an expression's use-defs (if any)
	// to an existing set of UDs.
	void AddInExprUDs(UDs uds, const Expr* e);

	// Add an ID into an existing set of UDs.
	void AddID(UDs uds, const ID* id) const;

	// Returns a new use-def corresonding to given one but
	// with the definition of "id" removed.
	UDs RemoveID(const ID* id, const UDs& uds);

	// Similar, but updates the UDs in place.
	void RemoveUDFrom(UDs uds, const ID* id);

	// Adds in the additional UDs to the main UDs.  Always
	// creates a new use_def and updates main_UDs to point to it.
	void FoldInUDs(UDs& main_UDs, const UDs& u1, const UDs& u2 = nullptr);

	// Adds in the given UDs to those already associated with s.
	void UpdateUDs(const Stmt* s, const UDs& uds);

	// Returns a new use-def corresponding to the union of 2 or 3 UDs.
	UDs UD_Union(const UDs& u1, const UDs& u2,
			const UDs& u3 = nullptr) const;

	// The given statement uses a (shallow) copy of the given UDs.
	UDs UseUDs(const Stmt* s, UDs uds);

	// Sets the given statement's UDs to a new UD set corresponding
	// to the union of the given UDs and those associated with the 
	// given expression.
	UDs CreateExprUDs(const Stmt* s, const Expr* e, const UDs& uds);

	// The given statement takes ownership of the given UDs.
	UDs CreateUDs(const Stmt* s, UDs uds);

	// Note, the value in this could be nullptr.
	std::unordered_map<const Stmt*, UDs> use_defs_map;

	// The following stores statements whose use-defs are
	// currently copies of some other statement's use-defs.
	std::unordered_set<const Stmt*> UDs_are_copies;

	// Track the statements we've processed.  This lets us dump
	// things out in order, even though the main map is unordered.
	std::vector<const Stmt*> stmts;

	// For a given expression statement, maps it to its successor
	// (the statement that will execute after it).  We need this
	// because we track UDs present at the *beginning* of
	// a statement, not at its end; those at the end are
	// the same as those at the beginning of the successor.
	std::unordered_map<const Stmt*, const Stmt*> successor;

	// Loop bodies have two successors, and it's important to
	// track both because sometimes a relevant UD will be present
	// in only one or the other.
	std::unordered_map<const Stmt*, const Stmt*> successor2;

	Stmt* body;
	Reducer* rc;
};
