"""
Enhanced WAF Review Module - Pagination & Firebase Integration
This module adds:
1. Pagination with "Question X of Y" navigation
2. Firebase database persistence
3. Auto-save functionality
4. Progress tracking

USAGE:
Replace the render_questions_section function in waf_review_module.py with this enhanced version
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional

def render_questions_with_pagination(assessment: Dict, questions: List, pillar_filter: Optional[str] = None):
    """
    Enhanced question rendering with pagination and Firebase persistence
    
    Features:
    - Shows "Question X of Y"
    - Next/Previous navigation
    - Firebase auto-save
    - Progress tracking
    
    CRITICAL: 'questions' parameter must be the COMPLETE list of all 205 questions
              for accurate scoring calculation
    """
    
    # Import Firebase helper
    try:
        from firebase_database_helper import save_assessment_to_firebase, auto_sync_response
        FIREBASE_AVAILABLE = st.session_state.get('firebase_initialized', False)
    except:
        FIREBASE_AVAILABLE = False
    
    # IMPORTANT: Keep reference to ALL questions for scoring
    all_questions = questions
    
    # Filter questions by pillar for DISPLAY only
    if pillar_filter and pillar_filter != "All":
        filtered_questions = [q for q in questions if q.pillar.value == pillar_filter]
    else:
        filtered_questions = questions
    
    total_questions = len(filtered_questions)
    
    if total_questions == 0:
        st.warning("No questions available")
        return
    
    # Initialize pagination state
    if 'current_question_index' not in st.session_state:
        st.session_state.current_question_index = 0
    
    # Ensure index is within bounds
    if st.session_state.current_question_index >= total_questions:
        st.session_state.current_question_index = 0
    
    current_index = st.session_state.current_question_index
    current_question = filtered_questions[current_index]
    
    # ============================================================================
    # PAGINATION CONTROLS (TOP)
    # ============================================================================
    
    st.markdown("---")
    
    # Progress bar
    answered_count = len([q for q in filtered_questions if q.id in assessment.get('responses', {})])
    progress = answered_count / total_questions if total_questions > 0 else 0
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        st.metric("Progress", f"{answered_count}/{total_questions}")
    
    with col2:
        st.progress(progress, text=f"{int(progress * 100)}% Complete")
    
    with col3:
        if FIREBASE_AVAILABLE:
            st.caption("✅ Auto-saving to Firebase")
        else:
            st.caption("⚠️ Firebase not connected")
    
    # Navigation buttons
    nav_col1, nav_col2, nav_col3, nav_col4, nav_col5 = st.columns([1, 1, 2, 1, 1])
    
    with nav_col1:
        if st.button("⏮️ First", disabled=(current_index == 0), use_container_width=True):
            st.session_state.current_question_index = 0
            st.rerun()
    
    with nav_col2:
        if st.button("◀️ Previous", disabled=(current_index == 0), use_container_width=True):
            st.session_state.current_question_index = max(0, current_index - 1)
            st.rerun()
    
    with nav_col3:
        st.markdown(f"### Question {current_index + 1} of {total_questions}")
    
    with nav_col4:
        if st.button("Next ▶️", disabled=(current_index >= total_questions - 1), use_container_width=True):
            st.session_state.current_question_index = min(total_questions - 1, current_index + 1)
            st.rerun()
    
    with nav_col5:
        if st.button("Last ⏭️", disabled=(current_index >= total_questions - 1), use_container_width=True):
            st.session_state.current_question_index = total_questions - 1
            st.rerun()
    
    st.markdown("---")
    
    # ============================================================================
    # QUESTION DISPLAY
    # ============================================================================
    
    # Question header
    st.markdown(f"### 🔒 {current_question.id}: {current_question.text}")
    st.caption(f"**Category:** {current_question.pillar.value} - {current_question.category}")
    st.info(current_question.description)
    
    # Check for existing response
    current_response = assessment.get('responses', {}).get(current_question.id)
    default_index = current_response.get('choice_index', 0) if current_response else 0
    
    # Check for auto-detection
    detected_data = assessment.get('auto_detected', {}).get(current_question.id, {})
    is_auto_detected = detected_data.get('auto_detected', False)
    
    if is_auto_detected:
        st.success(f"✨ Auto-detected from AWS scan (Confidence: {detected_data.get('confidence', 0)}%)")
        with st.expander("📋 Evidence"):
            for evidence in detected_data.get('evidence', []):
                st.markdown(f"• {evidence}")
        
        override = st.checkbox("Override auto-detected answer", key=f"override_{current_question.id}")
    else:
        override = False
    
    # AI Assistance button
    if st.button("🤖 Get AI Help", key=f"ai_help_{current_question.id}"):
        with st.spinner("Getting AI assistance..."):
            from waf_review_module import get_ai_question_assistance
            ai_help = get_ai_question_assistance(current_question, assessment)
            st.session_state[f"ai_assist_{current_question.id}"] = ai_help
    
    # Display AI assistance if available
    if f"ai_assist_{current_question.id}" in st.session_state:
        ai_help = st.session_state[f"ai_assist_{current_question.id}"]
        with st.expander("🤖 AI Assistance", expanded=True):
            st.markdown(f"**Simplified Explanation:** {ai_help.get('simplified_explanation', '')}")
            st.markdown(f"**Why It Matters:** {ai_help.get('why_matters', '')}")
            st.markdown(f"**Recommendation:** {ai_help.get('recommendation', '')}")
            st.markdown(f"**Example:** {ai_help.get('example', '')}")
            st.markdown("**Implementation Steps:**")
            st.markdown(ai_help.get('implementation_steps', ''))
    
    # Answer choices
    st.markdown("### Select your answer:")
    
    response_key = f"response_{current_question.id}"
    selected_choice = st.radio(
        "Choose one:",
        range(len(current_question.choices)),
        format_func=lambda i: f"{current_question.choices[i].risk_level.icon} {current_question.choices[i].text}",
        key=response_key,
        index=default_index,
        disabled=(is_auto_detected and not override)
    )
    
    # Show guidance for selected choice
    if selected_choice is not None:
        st.caption(f"💬 **Guidance:** {current_question.choices[selected_choice].guidance}")
    
    # Notes
    notes_default = ""
    if is_auto_detected and not override:
        notes_default = "Auto-detected from AWS scan\n" + "\n".join([f"• {e}" for e in detected_data.get('evidence', [])])
    elif current_response:
        notes_default = current_response.get('notes', '')
    
    notes = st.text_area(
        "Additional Notes & Evidence",
        value=notes_default,
        key=f"notes_{current_question.id}",
        placeholder="Add context, evidence, or observations that support your answer...",
        height=100
    )
    
    # ============================================================================
    # SAVE BUTTON (WITH FIREBASE INTEGRATION)
    # ============================================================================
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if st.button("💾 Save Response", key=f"save_{current_question.id}", use_container_width=True, type="primary"):
            # Prepare response data
            response_data = {
                'choice_index': selected_choice,
                'choice_text': current_question.choices[selected_choice].text,
                'risk_level': current_question.choices[selected_choice].risk_level.label,
                'points': current_question.choices[selected_choice].points,
                'notes': notes,
                'timestamp': datetime.now().isoformat(),
                'ai_assisted': f"ai_assist_{current_question.id}" in st.session_state,
                'auto_detected': is_auto_detected,
                'overridden': (is_auto_detected and override),
                'scan_confidence': detected_data.get('confidence', 0) if is_auto_detected else 0
            }
            
            # Save to session state
            if 'responses' not in assessment:
                assessment['responses'] = {}
            
            assessment['responses'][current_question.id] = response_data
            
            # ======================================================================
            # CALCULATE SCORES - FIX FOR 0 SCORE ISSUE
            # CRITICAL: Use ALL questions (all_questions), NOT filtered questions!
            # ======================================================================
            # Import scoring helper
            try:
                from assessment_scoring_helper import calculate_assessment_scores
                # IMPORTANT: Pass all_questions (all 205), not filtered_questions!
                calculate_assessment_scores(assessment, all_questions)
            except Exception as e:
                # Fallback: Manual calculation if helper not available
                # Use all_questions for correct calculation
                total_points = sum(r.get('points', 0) for r in assessment['responses'].values())
                max_points = len(all_questions) * 100
                assessment['overall_score'] = round((total_points / max_points * 100), 1) if max_points > 0 else 0
                assessment['progress'] = round((len(assessment['responses']) / len(all_questions) * 100), 1)
                # Also show the error for debugging
                st.error(f"Scoring calculation error: {str(e)}")
            
            # Update timestamp
            assessment['updated_at'] = datetime.now().isoformat()
            
            # Track AI assistance
            if f"ai_assist_{current_question.id}" in st.session_state:
                if 'ai_assistance_used' not in assessment:
                    assessment['ai_assistance_used'] = 0
                assessment['ai_assistance_used'] += 1
                del st.session_state[f"ai_assist_{current_question.id}"]
            
            # Save to Firebase if available
            if FIREBASE_AVAILABLE:
                assessment_id = assessment.get('assessment_id', 'default')
                
                # Try auto-sync first (lightweight)
                sync_success = auto_sync_response(assessment_id, current_question.id, response_data)
                
                if not sync_success:
                    # Fallback to full save
                    success, message = save_assessment_to_firebase(assessment_id, assessment)
                    if success:
                        st.success("✅ Response saved to Firebase!")
                    else:
                        st.warning(f"⚠️ Saved locally but Firebase sync failed: {message}")
                else:
                    st.success("✅ Response saved successfully!")
            else:
                st.success("✅ Response saved locally!")
                st.info("💡 Enable Firebase to persist data across sessions")
            
            # Auto-advance to next question
            if current_index < total_questions - 1:
                st.session_state.current_question_index = current_index + 1
            
            st.rerun()
    
    with col2:
        if st.button("⏭️ Skip", key=f"skip_{current_question.id}", use_container_width=True):
            if current_index < total_questions - 1:
                st.session_state.current_question_index = current_index + 1
                st.rerun()
    
    # ============================================================================
    # QUESTION NAVIGATION MAP (BOTTOM)
    # ============================================================================
    
    st.markdown("---")
    st.markdown("### 📍 Question Navigator")
    
    # Group questions in rows of 10
    questions_per_row = 10
    rows = [filtered_questions[i:i + questions_per_row] for i in range(0, len(filtered_questions), questions_per_row)]
    
    for row_idx, row_questions in enumerate(rows):
        cols = st.columns(len(row_questions))
        for col_idx, q in enumerate(row_questions):
            q_idx = row_idx * questions_per_row + col_idx
            is_answered = q.id in assessment.get('responses', {})
            is_current = q_idx == current_index
            
            # Button styling
            if is_current:
                button_type = "primary"
                button_label = f"▶ {q_idx + 1}"
            elif is_answered:
                button_type = "secondary"
                button_label = f"✓ {q_idx + 1}"
            else:
                button_type = "secondary"
                button_label = f"{q_idx + 1}"
            
            with cols[col_idx]:
                if st.button(
                    button_label,
                    key=f"nav_q_{q.id}",
                    use_container_width=True,
                    type=button_type,
                    help=f"{q.text[:50]}..."
                ):
                    st.session_state.current_question_index = q_idx
                    st.rerun()
    
    # Best practices
    with st.expander("📚 Best Practices & Guidance"):
        for bp in current_question.best_practices:
            st.markdown(f"• {bp}")
        
        st.markdown(f"[📖 AWS Documentation]({current_question.help_link})")
        
        if current_question.aws_services:
            st.markdown(f"**AWS Services:** {', '.join(current_question.aws_services)}")
    
    st.markdown("---")

# Export the function
__all__ = ['render_questions_with_pagination']