Jekyll::Hooks.register :site, :post_write do |site|
  sitemap = File.join(site.dest, "sitemap.xml")
  if File.exist?(sitemap)
    content = File.read(sitemap)

    # jekyll-sitemap adds xsi attributes on <urlset>; Google Search Console sometimes
    # reports "Couldn't fetch" for *.github.io until they are removed (jekyll-sitemap#320).
    content = content.gsub(
      / xmlns:xsi="[^"]*" xsi:schemaLocation="[^"]*"/,
      ""
    )

    # remove <url> blocks for /tags/ and /categories/
    filtered = content.gsub(
      %r{<url>\s*<loc>https?://[^<]*/(tags|categories)/.*?</url>}m,
      ""
    )

    File.write(sitemap, filtered)
  end
end