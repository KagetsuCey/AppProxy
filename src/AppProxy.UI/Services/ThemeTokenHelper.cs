using System.Windows;
using System.Windows.Media;

namespace AppProxy.UI.Services;

public static class ThemeTokenHelper
{
    public static void ApplySemanticTokens(bool isDark)
    {
        if (Application.Current is null) return;
        var res = Application.Current.Resources;

        if (isDark)
        {
            SetBrush(res, "AppAccentBrush", "#60A5FA");
            SetBrush(res, "AppAccentSoftBrush", "#243B82F6");
            SetBrush(res, "AppAccentBorderBrush", "#5060A5FA");

            SetBrush(res, "SemanticSuccessBrush", "#34D399");
            SetBrush(res, "SemanticSuccessBgBrush", "#2210B981");
            SetBrush(res, "SemanticSuccessBorderBrush", "#4834D399");

            SetBrush(res, "SemanticWarningBrush", "#FBBF24");
            SetBrush(res, "SemanticWarningBgBrush", "#22F59E0B");
            SetBrush(res, "SemanticWarningBorderBrush", "#48FBBF24");

            SetBrush(res, "SemanticErrorBrush", "#F87171");
            SetBrush(res, "SemanticErrorBgBrush", "#22EF4444");
            SetBrush(res, "SemanticErrorBorderBrush", "#48F87171");

            SetBrush(res, "SemanticInfoBrush", "#60A5FA");
            SetBrush(res, "SemanticInfoBgBrush", "#223B82F6");
            SetBrush(res, "SemanticInfoBorderBrush", "#4860A5FA");

            SetBrush(res, "SemanticPurpleBrush", "#A78BFA");
            SetBrush(res, "SemanticPurpleBgBrush", "#228B5CF6");
            SetBrush(res, "SemanticPurpleBorderBrush", "#48A78BFA");

            SetBrush(res, "SemanticTealBrush", "#2DD4BF");
            SetBrush(res, "SemanticTealBgBrush", "#2214B8A6");
            SetBrush(res, "SemanticTealBorderBrush", "#482DD4BF");

            SetBrush(res, "SemanticNeutralBgBrush", "#18FFFFFF");
            SetBrush(res, "SemanticNeutralBorderBrush", "#26FFFFFF");

            SetBrush(res, "NavRailBackgroundBrush", "#14000000");
            SetBrush(res, "NavItemSelectedBrush", "#1FFFFFFF");
            SetBrush(res, "CardHoverBackgroundBrush", "#12FFFFFF");
            SetBrush(res, "CardHoverBorderBrush", "#38FFFFFF");
            SetBrush(res, "SubtleDividerBrush", "#1AFFFFFF");
            SetBrush(res, "StatusBarBackgroundBrush", "#18000000");
            SetBrush(res, "DropzoneBackgroundBrush", "#143B82F6");
            SetBrush(res, "IconContainerBgBrush", "#14FFFFFF");
            SetBrush(res, "BrandBadgeStartBrush", "#2563EB");
            SetBrush(res, "BrandBadgeEndBrush", "#7C3AED");
        }
        else
        {
            SetBrush(res, "AppAccentBrush", "#2563EB");
            SetBrush(res, "AppAccentSoftBrush", "#1A2563EB");
            SetBrush(res, "AppAccentBorderBrush", "#402563EB");

            SetBrush(res, "SemanticSuccessBrush", "#059669");
            SetBrush(res, "SemanticSuccessBgBrush", "#18059669");
            SetBrush(res, "SemanticSuccessBorderBrush", "#40059669");

            SetBrush(res, "SemanticWarningBrush", "#D97706");
            SetBrush(res, "SemanticWarningBgBrush", "#1AD97706");
            SetBrush(res, "SemanticWarningBorderBrush", "#40D97706");

            SetBrush(res, "SemanticErrorBrush", "#DC2626");
            SetBrush(res, "SemanticErrorBgBrush", "#18DC2626");
            SetBrush(res, "SemanticErrorBorderBrush", "#40DC2626");

            SetBrush(res, "SemanticInfoBrush", "#2563EB");
            SetBrush(res, "SemanticInfoBgBrush", "#182563EB");
            SetBrush(res, "SemanticInfoBorderBrush", "#402563EB");

            SetBrush(res, "SemanticPurpleBrush", "#7C3AED");
            SetBrush(res, "SemanticPurpleBgBrush", "#187C3AED");
            SetBrush(res, "SemanticPurpleBorderBrush", "#407C3AED");

            SetBrush(res, "SemanticTealBrush", "#0D9488");
            SetBrush(res, "SemanticTealBgBrush", "#180D9488");
            SetBrush(res, "SemanticTealBorderBrush", "#400D9488");

            SetBrush(res, "SemanticNeutralBgBrush", "#10000000");
            SetBrush(res, "SemanticNeutralBorderBrush", "#1F000000");

            SetBrush(res, "NavRailBackgroundBrush", "#08000000");
            SetBrush(res, "NavItemSelectedBrush", "#14000000");
            SetBrush(res, "CardHoverBackgroundBrush", "#0A000000");
            SetBrush(res, "CardHoverBorderBrush", "#28000000");
            SetBrush(res, "SubtleDividerBrush", "#14000000");
            SetBrush(res, "StatusBarBackgroundBrush", "#0A000000");
            SetBrush(res, "DropzoneBackgroundBrush", "#102563EB");
            SetBrush(res, "IconContainerBgBrush", "#0C000000");
            SetBrush(res, "BrandBadgeStartBrush", "#2563EB");
            SetBrush(res, "BrandBadgeEndBrush", "#6366F1");
        }
    }

    private static void SetBrush(ResourceDictionary resources, string key, string hex)
    {
        var color = (Color)ColorConverter.ConvertFromString(hex);
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        resources[key] = brush;
    }
}
