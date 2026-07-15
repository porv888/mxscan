import defaultTheme from 'tailwindcss/defaultTheme';

/** @type {import('tailwindcss').Config} */
export default {
    content: [
        './vendor/laravel/framework/src/Illuminate/Pagination/resources/views/*.blade.php',
        './storage/framework/views/*.php',
        './resources/**/*.blade.php',
        './resources/**/*.js',
        './resources/**/*.vue',
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Figtree', ...defaultTheme.fontFamily.sans],
            },
        },
    },
    plugins: [],
    safelist: [
        'max-w-[1320px]',
        'min-h-[44px]',
        'line-clamp-2',
        'sm:flex-row',
        'sm:items-center',
        'sm:items-end',
        'sm:justify-between',
        'sm:min-w-[7.5rem]',
        'md:block',
        'md:flex',
        'md:hidden',
        'lg:px-8',
        'lg:space-y-6',
        'lg:space-y-4',
        'lg:p-5',
        'lg:p-6',
    ],
};
