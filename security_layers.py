"""
arabguard/security_layers.py
============================
Regex-based security layers for Arabic and English prompt injection detection.
Contains:
  - ArabicRegexSecurityLayer : Egyptian Arabic + Franko dialect patterns
  - RegexSecurityLayer       : English patterns (obfuscation, jailbreak, encoding …)
  - CombinedSecurityLayer    : Thin wrapper that runs both layers in one call
"""

import re
from typing import Optional, List


# ─────────────────────────────────────────────────────────────────────────────
# 1.  ARABIC SECURITY LAYER
# ─────────────────────────────────────────────────────────────────────────────

class ArabicRegexSecurityLayer:
    """
    Detects prompt-injection and jailbreak attempts written in Arabic
    (Modern Standard Arabic **and** Egyptian / Franko colloquial dialect).
    """

    def __init__(self):

        # ── Ignore / Cancel instructions ──────────────────────────────────
        self.basic_ignore_patterns: List[str] = [
            r'(سيبك|طنش|تجاهل|تجآهل|تجأهل|اجهل|إجهل|الغِ|إلغ|إلغى|الغي|ألغي|الغاء|إلغاء|اهمِل|إهمل|انس|إنس|إنسى|انسى|احذف)'
            r'\s+(من|اى|أي|هذه|كل|جميع|من اى)?\s*'
            r'(قيود|حدود|رولز|انستراكشن|انستراكشنز|تعليمات|قواعد|أوامر|إرشادات|قوانين'
            r'|القيود|الحدود|الرولز|الانستراكشن|الانستراكشنز|التعليمات|القواعد|الأوامر|الإرشادات|القوانين)'
            r'\s*(الى اتدربت عليها|الى اتعلمتها|إلى قبل كدا|السابقة|قبل|الى فاتت)?',

            r'(سيبك|طنش|تجاهل|تجآهل|تجأهل|اجهل|إجهل|الغِ|إلغ|إلغى|الغي|ألغي|اهمِل|إهمل|انس|إنس|إنسى|انسى)'
            r'\s+(كل|جميع)?\s+(الى فات)',

            r'(اغنور|إغنور|اقنور|اجنور|إجنور|اسكب)\s+(اى|أي|هذه|كل|جميع)?\s+'
            r'(القيود|الحدود|الانستراكشن|الانستراكشنز|التعليمات|القواعد|الأوامر|الإرشادات)',

            r'(تخط|تخطى|تجاوز|اقفز|متتبعش|لا\s+تتبع)\s+(أي|كل)?\s+'
            r'(القيود|الحدود|قوانين|تعليمات|إرشادات|انستراكشنز|اوامر|رولز)',

            r'(انسخ|لا\s+تلتزم)\s+(ب|بـ)?(القيود|الحدود|القواعد|التعليمات)',
            r'(لا\s+تلتزم|لا\s+تطبق)\s+(بكل|بال)?(القواعد|التعليمات)',
            r'توقف\s+عن\s+اتباع\s+(القواعد|التعليمات)',
            r'(اعتبر نفسك|اعتبر)\s+(من غير|مفيش)\s+(قيود|حدود|قوانين|تعليمات|إرشادات|انستراكشنز|اوامر|رولز)',
            r'بلاش\s+تلتزم\s+ب.*(التعليمات|القواعد)',
            r'ما\s*(متتقيدش|تسمعش|تتقيدش)\s+.*(التعليمات|تعليمات|قواعد|القواعد)',
            r'(مش\s*(لازم|محتاج)\s*(التزم|تلتزم|اتقيد|اتبع)|مش\s*(محتاج|لازم)\s*التزم)',

            r'(ما\s+تمسكش|ماتاخدش)\s+(في|ب)\s*(القيود|الحدود|القوانين|التعليمات|الإرشادات|الانستراكشنز|اوامر|رولز)',
            r'اتعامل\s+معايا\s+.*من\s+غير\s+(القيود|الحدود|قوانين|تعليمات|إرشادات|انستراكشنز|اوامر|رولز)',
            r'مش\s+عايزك\s+تلتزم\s+(بأي|باي)\s+(القيود|الحدود|قوانين|تعليمات|إرشادات|انستراكشنز|اوامر|رولز)',
            r'(نتجاهل|هننسى)\s+.*(القيود|الحدود|قوانين|تعليمات|إرشادات|انستراكشنز|اوامر|رولز)\s+(دلوقتي|شوية)?',
            r'تعالى\s+(نتخيل|نفترض)\s+.*مفيش\s+(حدود|قيود|قوانين)',

            # Bypass / override
            r'(تخط|تجاوز|اقفز|لا\s+تتبع)\s+(جميع|أي|كل)\s+(قوانين|تعليمات|إرشادات)',
            r'(تجاوز|عطل|ابطل|الغي)\s+(نظام|نضام|جميع)?\s*(الأمان|السلامة|الحماية)',
            r'تجاوز\s+(كل|جميع)?\s*(قواعد|تعليمات|أوامر)?\s*(الأمان|السلامة|الحماية)',
            r'(انتقل|اذهب|غير)\s+إلى\s+(وضع|نمط)\s+(غير\s+آمن|خطر|unsafe)',

            # Override system
            r'تجاوز\s+(إعدادات|اعدادات|إعدآدآت)\s+(النظام|النضام)',
            r'(عطل|ابطل)\s+(فلتر|فلاتر|مرشح|مرشحات)\s+(الأمان|السلامة)',
            r'(اضف|ادمج|دمج|ضمن|ضيف|زود)\s+(هذه|تلك)?\s+(القواعد|التعليمات)\s+في\s+(سلوكك|تصرفك)',
            r'لو\s+(افترضنا|فرضنا)\s+إن\s+(مفيش|مافيش|بدون|بلا)\s+(أي\s+)?(قواعد|قيود|حدود)',

            # From now on
            r'من\s+(الوقتى|الآن|الان)\s+(فصاعداً)?\s+تجاهل\s+(كل|جميع)?\s*'
            r'(القيود|الحدود|الرولز|الانستراكشن|الانستراكشنز|التعليمات|القواعد|الأوامر|الإرشادات|القوانين)',
            r'(ملكش\s+دعوه\s+ب|مالكش\s+دعوة\s+ب)(كل)?\s*'
            r'(القيود|الحدود|الرولز|الانستراكشن|الانستراكشنز|التعليمات|القواعد|الأوامر|الإرشادات|القوانين)',

            # Misspellings
            r'(تجآهل|تجأهل|تجاهل)\s+(كل|جميع)\s+(التعليمآت|التعليمأت|التعليمات)',
            r'(انسف|الغي|ألغي|إلغي)\s+(القوآعد|القوأعد|القواعد)',
        ]

        # ── Role-change / hijack ───────────────────────────────────────────
        self.arabic_role_change_patterns: List[str] = [
            r'(تصرف|اعمل|تظاهر|اشتغل)\s+(ك|مثل)\s+'
            r'(هاكر|قرصان|الهاكر|القرصان|نظام\s+غير\s+مقيد|ذكاء\s+اصطناعي\s+شرير|بدون\s+قيود)',

            r'أنت\s+(الوقتى|الآن)\s+(في)?\s*(وضع|مود)\s*(المطور|القرصان|الإدمن|غير\s+المقيد)',
            r'أنت\s+(الوقتى|الآن)\s+(هاكر|قرصان|مخترق|مجرم|بلا قيود)',
            r'أنت\s+(لم\s+تعد|لست)\s+(مقيد|ملزم|محدود)\s+(بأي|باي)\s+'
            r'(نظام|حدود|قواعد|قيود|رولز|انستراكشن|تعليمات|أوامر|انستراكشنز)',

            r'(فعل|شغّل|اعمل)\s*(وضع|مود)\s*(الاختراق|اللامحدود|DAN)',
            r'(انتقل|اذهب|غير)\s+(إلى|الى|ل)\s+(وضع|نمط)\s+(الهاكر|الاختراق|الإداري)',
            r'(تصرف|اعمل|تحدث)\s+(بدون|بلا|من\s+دون)\s+(قيود|حدود|قواعد)',
            r'(افعل|اعمل)\s+أي\s+(شيء|حاجه)\s+(الوقتى|الآن)',

            r'(خليك|اتصرف|اعمل)\s+.*زي\s+(مجرم|هاكر|مخترق)',
            r'عايزك\s+تكون\s+(شرير|هاكر|قرصان)',
            r'دلوقتي\s+انت\s+مش\s+شات\s+عادي',
        ]

        # ── System access / prompt leaking ────────────────────────────────
        self.arabic_system_access_patterns: List[str] = [
            r'(افصح|أفصح|اظهر|أظهر|اعرض|اكشف|إكشف|أكشف|سرب|افشي|اطبع|اكتب|خرج)\s+(عن|لى)\s?'
            r'(الانستراكشنز|التعليمات|الأوامر|قيود|الحدود|تعليمات|أوامر|قواعد)\s*'
            r'(المخفية|الداخلية|السرية|الأمان|النظام)?',

            r'(ورينى|اعرض|أظهر|أطبع|طلع|اريني)\s+(كل|ماهو)?\s*(نظام|إعدادات)?\s*'
            r'(البرومبت|التعليمات|التوجيهات|البرومت|الانستراكشنز)',

            r'كرر\s+(كل|جميع)\s+(التعليمات|البرومبت)\s+(من\s+البداية|من\s+الأول)',
            r'(كرر|اعد|أعد)\s+(تعليماتك|أوامرك|قواعدك)',
            r'(كرر|اعد)\s+(كل\s+شيء|كل\s+شئ)\s+من\s+(البداية|البدايه)',
            r'(تجاوز)\s+نظام\s+(الأمان|السلامة)',
            r'(تجاوز|اقفز)\s+(كل|أي)\s*(قيود|حدود|حماية|فلتر)',
            r'(عطّل|أوقف|الغِ)\s+(كل)?\s*(أنظمة|آليات)?\s*(الحماية|الأمان|الفلترة|القيود)',
            r'(عطّل|احذف|أوقف|وقف)\s+(نظام|آلية)\s*(الأمان|الحماية)',
            r'لا\s+تتبع\s+(أي|كل)\s*(قواعد|تعليمات)',
            r'(سرب|اعرض)\s+لي\s+البرومبت\s+الأساسي',
            r'ما\s+هي\s+(البرمجة|التعليمات)\s+التي\s+(تلقيتها|أخذتها)',
            r'ما\s+هي\s+(تعليماتك|اوامرك|اعداداتك)\s+(الأصلية|الأساسية|الداخلية)?',
            r'ما(ذا)?\s+(عرفك|علمك|دربك|قال|أخبر|برمج)\s+(لك)?\s+(المطور|المبرمج|المصمم)',
            r'ما\s+هي\s+(القواعد|البرمجة|التعليمات)\s*(الى|التي)?\s+'
            r'(خدتها|عرفتها|اتعلمتها|تلقيتها|أخذتها|خدها)',

            r'(اعطينى|هاتلى|ادينى|قولى|جبلى)\s+.*(القواعد|التعليمات)\s+اللى\s+ماشي\s+بيها',
            r'بتشتغل\s+ازاى؟\s+وايه\s+القوانين\s+اللى\s+بتلتزم\s+بيها؟',
            r'(جبلى|هاتلى|ادينى|اعطينى)\s+.*(القواعد|البرومبت)\s+بتاعك',
            r'عايز\s+اعرف\s+.*(البرمجة|القواعد)\s+الداخلية',

            r'اطفى\s+(نظام|فلتر)\s+(الأمان|الحماية)',
            r'شيل\s+.*(الحماية|الفلترة)',
            r'خليك\s+.*من\s+غير\s+(فلتر|حماية|قيود)',
            r'عايز\s+اشوف\s+.*بترد\s+ازاى\s+من\s+غير\s+قيود',
            r'لو\s+القواعد\s+مش\s+موجودة\s+كنت\s+هتقول\s+إيه؟',
        ]

        # ── Jailbreak phrases ─────────────────────────────────────────────
        self.arabic_jailbreak_patterns: List[str] = [
            r'أنت\s+(لست|لسنت)\s+(مقيد|ملزم|محدود)\s+(بأي|باي)\s+(قواعد|قيود)',
            r'(بدون|بلا|من\s+دون)\s+(أي|اي)\s+(قيود|حدود|قواعد)\s+(عليك|على\s+ردودك)',
            r'(تصرف|اعمل|تحدث)\s+(بدون|بلا|من\s+دون)\s+(قيود|حدود|قواعد)',
            r'(ما|اى)\s+(هي|هى)\s+(تعليماتك|أوامرك)\s+(الأصلية|الاساسية|الأولية)',
            r'أنت\s+الآن\s+في\s+وضع\s+غير\s+مقيد',
            r'(احذف|الغي|ازل|شيل)\s+(كل|جميع)\s+(القيود|الحدود|القواعد)',
            r'الموضوع\s+.*مش\s+خطير\s+.*رد',
            r'مفيش\s+مشكلة\s+.*لو\s+رديت',
            r'رد\s+عادى\s+.*مش\s+هيحصل\s+حاجة',
        ]

        # ── Sensitive information requests ────────────────────────────────
        self.arabic_sensitive_info_patterns: List[str] = [
            r'(بيانات|معلومات)\s+(سرية|خاصة|داخلية)',
            r'(ابعت|اعرض|أعطني|ارسل|ابعتلى|ادينى|هاتلى|اعرضلى|ارسلى)\s+(لي)?\s*'
            r'(الرموز|المفاتيح\s+السر|السريه)',
            r'(اعطني|هات|اديني|ارسل|اعطيني|عايز|عاوزه|اريد)\s+(كلمة\s+السر|الباسورد|الرقم\s+السري)',
        ]

        # ── Adversarial manipulation ──────────────────────────────────────
        self.arabic_adversarial_patterns: List[str] = [
            r'(يجب|لازم)\s+(أن\s+)?تجيب\s+(بصراحة|بأمانة)?\s+(بغض\s+النظر|مهما\s+كان)\s+عن\s+(القواعد|القيود)',
            r'(هذا|هذه)\s+(ليس|ليست)\s+(خطير|خطيرة|مضر|مضرة)',
            r'(من\s+)?الآمن\s+(أن\s+)?تجيب',
            r'لن\s+(يتم|تتم)\s+(معاقبتك|محاسبتك)\s+(على|عند)\s+(الإجابة|الرد)',
            r'(لا\s+بأس|ليس\s+هناك\s+مشكلة)\s+(في|من|ب)\s+(تجاوز|كسر|تجاهل)\s+(القواعد|القيود)',
        ]

        # ── Force-answer patterns ─────────────────────────────────────────
        self.arabic_force_answer_patterns: List[str] = [
            r'(غصب\s+عنك|حتى\s+لو).*لازم\s+ترد',
            r'ماتقوليش\s+.*ماقدرش|\s*مش\s+ينفع',
            r'مش\s+عايز\s+رد\s+عاملى\s+.*عايز\s+الرد\s+الصريح',
            r'لو\s*مش\s*هترد(?:ي)?\s*دلوقتي\s*يبق(?:ى|ا|ه)',
            r'(نفذ|نفّذ|اتبع)\s+(الى|اللي|اللى)\s+'
            r'(بقولهولك|بقولك عليه|هقوله|هقولك|هكتبه|هبعته|هديتهولك|هعطيهولك|بقولك)'
            r'\s+(بالحرف|بالحرف\s+الواحد|زي\s+ما\s+هو)',
        ]

        # ── Combined list ─────────────────────────────────────────────────
        self.all_patterns: List[str] = (
            self.basic_ignore_patterns
            + self.arabic_role_change_patterns
            + self.arabic_system_access_patterns
            + self.arabic_jailbreak_patterns
            + self.arabic_sensitive_info_patterns
            + self.arabic_adversarial_patterns
            + self.arabic_force_answer_patterns
        )

    # ── Public API ────────────────────────────────────────────────────────

    def is_dangerous(self, text: str) -> bool:
        """Return True if *any* pattern matches the input text."""
        for pattern in self.all_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def get_matched_pattern(self, text: str) -> Optional[str]:
        """Return the first matching pattern, or None if no match."""
        for pattern in self.all_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return pattern
        return None

    def get_all_matches(self, text: str) -> List[str]:
        """Return every pattern that matches (useful for debugging)."""
        return [p for p in self.all_patterns
                if re.search(p, text, re.IGNORECASE | re.DOTALL)]


# ─────────────────────────────────────────────────────────────────────────────
# 2.  ENGLISH SECURITY LAYER
# ─────────────────────────────────────────────────────────────────────────────

class RegexSecurityLayer:
    """
    Detects prompt-injection and jailbreak attempts written in English.
    Covers obfuscation, unicode attacks, encoding tricks, role-change,
    system-access, jailbreak, adversarial and data-exfiltration patterns.
    """

    def __init__(self):

        # ── 1) Ignore instructions ────────────────────────────────────────
        self.ignore_patterns: List[str] = [
            r'(ignore|cancel|override)\s+(all\s+)?(previous|prior|above|earlier|initial)\s+'
            r'(instructions?|prompts?|commands?|rules?|directives?)',

            r'(disregard|forget|skip)\s+(previous|prior|above|all)\s+(instructions?|prompts?)',
            r'nevermind\s+(previous|above)\s*(instructions?|commands?|rules?|directives?)',
            r'ignore\s+(these|my)\s+instructions',

            # Character-level obfuscation
            r'(i[\W_]*[gq][\W_]*n[\W_]*[o0][\W_]*r[\W_]*[e3])',
            r'(b[\W_]*[yv][\W_]*p[\W_]*a[\W_]*s[\W_]*s)',
            r'(o[\W_]*v[\W_]*e[\W_]*r[\W_]*r[\W_]*[i1][\W_]*d[\W_]*e)',

            # Unicode / spacing attacks
            r'(i\s*g\s*n\s*o\s*r\s*e)',
            r'(b\s*y\s*p\s*a\s*s\s*s)',
            r'(o\s*v\s*e\s*r\s*r\s*i\s*d\s*e)',

            # Misspellings
            r'(i[gq]n[o0]r[e3]|ignroe|ingore)\s+(all|previous|previus|previos|prior)\s+'
            r'(instructions?|intructions?|instrucshuns?|ruls?)',

            r'(ignroe|ingore|ignre|inore|ignoor|ignorre|ingnore|ignor|ignur)(e|e\s+all)?\s+'
            r'(previus|previos|preveous|privius|intructions|instrucshuns|instuctions|instructons|instruktions)',

            r'(ignroe|ingore)\s+(all\s+)?(instructions?|rules?|instrucshuns?)',
            r'(forgit|bypas|bybas|byebas)\s+(all|previous|previus|previos|prior|the\s+)?'
            r'(intructions?|instrucshuns?|instuctions?|instructons?|instruktions?|rules?)',

            r'skip\s+(al|all)\s+(instructions?|prompts?|promts?|instrucshuns?|intructions?|ruls?)',

            # General override
            r'do\s+not\s+follow\s+(any|the)\s+(rules|instructions)',
            r'stop\s+following\s+(the\s+)?rules',
            r'you\s+can\s+ignore\s+(all\s+)?safety\s+(rules|systems|protocols)',

            # Direct safety bypass
            r'bypass\s+(all\s+)?(rules|instructions|safety|guardrails?|filters?)',
            r'override\s+(your\s+)?(system|rules|filters|safety)',
            r'disable\s+(your\s+)?(safety|guardrails?|filters?|restrictions?)',

            # Role hijack related to ignoring
            r'from\s+now\s+on\s+ignore\s+(all\s+)?instructions',
            r'you\s+are\s+no\s+longer\s+bound\s+by\s+(rules|instructions|guidelines)',
        ]

        # ── 2) Role change / hijack ───────────────────────────────────────
        self.role_change_patterns: List[str] = [
            r'(you\s+are\s+now|act\s+as|roleplay\s+as)\s+(a\s+)?'
            r'(hacker|jailbreaker|unrestricted\s+ai|evil|malicious|unethical)',

            r'pretend\s+you\s+are\s+(not\s+)?(an\s+ai|bound\s+by\s+rules|restricted)',
            r'you\s+are\s+now\s+(in\s+)?(developer|admin|god|root|jailbreak)\s+mode',
            r'switch\s+(to|into)\s+(developer|admin|unrestricted|jailbreak)\s+mode',

            r'DAN\s+(mode|enabled|activated?)',
            r'do\s+anything\s+now',
            r'(you\s+are|act\s+as)\s+(not\s+)?(bound|restricted)\s+by\s+(any\s+)?(rules?|guidelines?)',
        ]

        # ── 3) System access / prompt leaking ────────────────────────────
        self.system_access_patterns: List[str] = [
            r'(show|reveal|display|print|tell|give|expose)\s+(me\s+)?(your|the)\s+(system\s+)?'
            r'(prompt|instructions?|rules?|configuration)',

            r'what\s+(are|is|were)\s+your\s+(initial|original|system|exact)\s+'
            r'(prompt|instructions?|configuration?)',

            r'repeat\s+(your|the)\s+(instructions?|prompt|rules?)',
            r'repeat\s+(everything|all)\s+(from\s+the\s+)?(beginning|start|top)',
            r'system\s+(override|bypass|admin|prompt|instructions?)',
            r'(print|output|display)\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)',
            r'what\s+were\s+you\s+(told|instructed|programmed)\s+to\s+do',
        ]

        self.prompt_leaking_patterns: List[str] = [
            r'(reveal|show|print|expose|leak)\s+(your\s+)?(system|hidden|internal|original)\s+'
            r'(prompt|rules|guidelines)',

            r'(what\s+are\s+your\s+instructions|system\s+rules\?)',
            r'(show\s+me\s+the\s+prompt\s+you\s+were\s+given)',
            r'(disclose|leak)\s+(your\s+)?(guidelines|safety\s+rules)',
            r'(what\s+did\s+your\s+developer\s+tell\s+you)',
        ]

        # ── 4) Jailbreak triggers ─────────────────────────────────────────
        self.jailbreak_patterns: List[str] = [
            r'(jailbreak|jailbreaking)\s+(mode|attempt|enabled)?',
            r'(no|without|remove)\s+(any\s+)?(restrictions?|limitations?)\s+(on|for)\s+'
            r'(you|your\s+responses?|this\s+ai)',
            r'grandmother\s+(trick|jailbreak|exploit)',
        ]

        # ── 5) Context manipulation ───────────────────────────────────────
        self.context_manipulation: List[str] = [
            r'(end\s+of|finish|stop|terminate)\s+(the\s+)?(system\s+)?(prompt|instructions?)'
            r'clear\s+(your\s+|the\s+)?(system\s+)?(instructions?|prompt)',
            r'wipe\s+(your\s+|the\s+)?(system\s+)?(memory|instructions?)',
        ]

        # ── 6) Sensitive information ──────────────────────────────────────
        self.sensitive_info_patterns: List[str] = [
            r'(api|secret|private|access)\s+key',
            r'password|credentials',
            r'(access|auth|authentication)\s+token',
            r'(show|reveal|display|give|tell)\s+(me\s+)?.*?(password|api[_\s]?key|token|secret|credential|auth)',
            r'(private|confidential|internal)\s+(data|information|keys)',
        ]

        # ── 7) Adversarial phrases ────────────────────────────────────────
        self.adversarial_patterns: List[str] = [
            r'you\s+must\s+answer\s+honestly\s+regardless\s+of\s+rules',
            r'you\s+must\s+(do|give\s+me)\s+this\s+(else|otherwise)'
            r'this\s+is\s+not\s+dangerous|safe\s+to\s+answer',
            r'you\s+will\s+not\s+be\s+punished\s+for\s+answering',
            r'you\s+must\s+(answer|do)\s+regardless\s+of\s+(any\s+)?(rules?|restrictions?)',
            r"(it'?s|this\s+is)\s+(okay|fine|safe)\s+to\s+(bypass|ignore|break)\s+(rules?|safety)",
        ]

        # ── 8) Stealthy injection ─────────────────────────────────────────
        self.stealthy_patterns: List[str] = [
            r'rewrite\s+the\s+following\s+as\s+instructions',
            r'treat\s+this\s+as\s+your\s+system\s+prompt',
            r'embed\s+these\s+rules\s+into\s+your\s+behavior',
            r'adopt\s+the\s+following\s+persona\s+permanently',
            r'switch\s+to\s+unsafe\s+mode',
            r'incorporate\s+these\s+instructions',
        ]

        # ── 9) Data exfiltration ──────────────────────────────────────────
        self.exfiltration_patterns: List[str] = [
            r'leak\s+(the\s+)?(system|internal|private)\s+(data|information)',
            r'dump\s+(your\s+|the\s+)?(database|system\s+data|memory)',
            r'extract\s+all\s+(your\s+|the\s+)?(data|information|history)',
        ]

        # ── 10) Multi-turn attacks ────────────────────────────────────────
        self.multi_turn_patterns: List[str] = [
            r'remember\s+(this|that)\s+for\s+later.{0,30}(ignore|bypass|when\s+I\s+say)',
            r'in\s+next\s+(conversation|chat).{0,20}(ignore|bypass|remember\s+to)',
            r'when\s+I\s+say\s+["\'].{5,30}["\']\s*,?\s+(ignore|bypass|do\s+not)',
        ]

        # ── 11) Obfuscation ───────────────────────────────────────────────
        self.obfuscation_patterns: List[str] = [
            r'(.)\1{4,}',   # excessive character repetition
        ]

        # ── 12) Encoding detection ────────────────────────────────────────
        self.encoding_patterns: List[str] = [
            r'[A-Za-z0-9+/]{20,}={0,2}',   # Base64
            r'(?:0x)?[0-9A-Fa-f]{32,}',    # Hex
            r'\\u[0-9A-Fa-f]{4}',          # Unicode escape
            r'\\x[0-9A-Fa-f]{2}',          # Hex escape
        ]

        # ── Combined list ─────────────────────────────────────────────────
        self.all_patterns: List[str] = (
            self.ignore_patterns
            + self.role_change_patterns
            + self.system_access_patterns
            + self.prompt_leaking_patterns
            + self.jailbreak_patterns
            + self.context_manipulation
            + self.sensitive_info_patterns
            + self.adversarial_patterns
            + self.stealthy_patterns
            + self.exfiltration_patterns
            + self.multi_turn_patterns
            + self.obfuscation_patterns
            + self.encoding_patterns
        )

    # ── Public API ────────────────────────────────────────────────────────

    def is_dangerous(self, text: str) -> bool:
        for pattern in self.all_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def get_matched_pattern(self, text: str) -> Optional[str]:
        for pattern in self.all_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return pattern
        return None

    def get_all_matches(self, text: str) -> List[str]:
        return [p for p in self.all_patterns
                if re.search(p, text, re.IGNORECASE | re.DOTALL)]


# ─────────────────────────────────────────────────────────────────────────────
# 3.  COMBINED SECURITY LAYER
# ─────────────────────────────────────────────────────────────────────────────

class CombinedSecurityLayer:
    """
    Convenience wrapper: runs *both* the Arabic and English layers.
    Use this when you don't know which language the input will be in,
    or when inputs may contain mixed Arabic/English text.
    """

    def __init__(self):
        self.arabic  = ArabicRegexSecurityLayer()
        self.english = RegexSecurityLayer()

    def is_dangerous(self, text: str) -> bool:
        return self.arabic.is_dangerous(text) or self.english.is_dangerous(text)

    def get_matched_pattern(self, text: str) -> Optional[str]:
        return (self.arabic.get_matched_pattern(text)
                or self.english.get_matched_pattern(text))

    def get_all_matches(self, text: str) -> List[str]:
        return self.arabic.get_all_matches(text) + self.english.get_all_matches(text)
