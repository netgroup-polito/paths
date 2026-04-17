:- dynamic derived_from/2.
:- dynamic trace_enabled/0.

trace_derivation(Subgoals, Head) :-
    call_all(Subgoals),
    (   trace_enabled,
        \+ derived_from(Head, _)
    ->  assertz(derived_from(Head, Subgoals))
    ;   true
    ).

call_all([]).
call_all([G|Gs]) :- call(G), call_all(Gs).

canbeComp(E,T) :-
    trace_derivation([assVul(E,T), not(defended(E,T))],
                     canbeComp(E,T)).

canbeComp(E1,T) :-
    trace_derivation([(contain(E1,E2); isContained(E1,E2)),
                      assComp(E2,T),
                      spread(E2,T,V),
                      not(defended(E1,T))],
                     canbeComp(E1,T)).

canbeComp(E1,T) :-
    trace_derivation([connect(E3,E1,E2),
                      assComp(E2,T),
                      spread(E2,T,V),
                      not(defended(E1,T)),
                      (assComp(E3,_); not(defended(E3,T)))],
                     canbeComp(E1,T)).

canbeComp(E1,T) :-
    trace_derivation([control(E1,E2),
                      assComp(E2,T),
                      spread(E2,T,V),
                      not(defended(E1,T))],
                     canbeComp(E1,T)).

canbeMalfun(E,M) :-
    trace_derivation([assComp(E,T), cause(T,M)],
                     canbeMalfun(E,M)).

canbeMalfun(E1,M) :-
    trace_derivation([depend(E1,E2), assMalfun(E2,M)],
                     canbeMalfun(E1,M)).

canbeVul(E,T) :-
    trace_derivation([exposed(E,V), exploitable(V,T)],
                     canbeVul(E,T)).

canbeVul(E,T) :-
    trace_derivation([assMalfun(E,M), induce(M,V), exploitable(V,T)],
                     canbeVul(E,T)).

canbeDet(E,T) :-
    trace_derivation([assComp(E,T), monitored(E,T)],
                     canbeDet(E,T)).

canbeRest(E) :-
    trace_derivation([assDet(E,T), replicated(E)],
                     canbeRest(E)).

canbeFix(E) :-
    trace_derivation([assMalfun(E,M), checked(E)],
                     canbeFix(E)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% DYNAMIC DECLARATIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

:- dynamic assVul/2, assComp/2, defended/2, assMalfun/2, assDet/2, assFix/2.
:- dynamic contain/2, isContained/2, depend/2, defended/2, monitored/2,
           replicated/1, checked/1, connect/3, control/2, spread/3.


